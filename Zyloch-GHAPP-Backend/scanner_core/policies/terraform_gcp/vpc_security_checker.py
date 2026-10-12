"""
GCP VPC Security Checker

Validates Google Cloud VPC resources (networks, subnetworks, firewall rules)
for security compliance including flow logging, public access restrictions,
and firewall rule configurations.
"""

from typing import List, Dict, Any
from scanner_core.models.violation import GCPPolicyViolation
from scanner_core.constants.gcp_policy_ids import GCPPolicyIDs


class VPCSecurityChecker:
    """Checker for VPC security policies"""

    def check(self, resources: dict) -> List[GCPPolicyViolation]:
        """
        Validate GCP VPC resources for security compliance.

        Args:
            resources: Dictionary of GCP resources from tfplan.json

        Returns:
            List of GCPPolicyViolation objects for non-compliant resources
        """
        violations = []

        # Check all VPC-related resource types
        violations.extend(self._check_compute_networks(resources))
        violations.extend(self._check_compute_subnetworks(resources))
        violations.extend(self._check_firewall_rules(resources))

        return violations

    def _check_compute_networks(self, resources: dict) -> List[GCPPolicyViolation]:
        """
        Validate google_compute_network resources.

        Checks:
        - auto_create_subnetworks should be false (manual control)
        """
        violations = []

        if "google_compute_network" not in resources:
            return violations

        for resource_name, resource in resources["google_compute_network"].items():
            # Check if auto_create_subnetworks is enabled
            auto_create = resource.get("auto_create_subnetworks", True)
            if auto_create is True:
                violations.append(
                    GCPPolicyViolation(
                        policy_id=GCPPolicyIDs.VPC_NETWORK_AUTO_SUBNETS,
                        severity="Medium",
                        resource_name=resource_name,
                        resource_type="google_compute_network",
                        message="VPC network must have auto_create_subnetworks set to false for manual subnet control",
                        guide="https://cloud.google.com/vpc/docs/vpc"
                    )
                )

        return violations

    def _check_compute_subnetworks(self, resources: dict) -> List[GCPPolicyViolation]:
        """
        Validate google_compute_subnetwork resources.

        Checks:
        - log_config must be enabled for flow logging
        - private_ip_google_access should be true
        """
        violations = []

        if "google_compute_subnetwork" not in resources:
            return violations

        for resource_name, resource in resources["google_compute_subnetwork"].items():
            # Check if flow logs are enabled
            log_config = resource.get("log_config")
            if not log_config or log_config is None:
                violations.append(
                    GCPPolicyViolation(
                        policy_id=GCPPolicyIDs.VPC_SUBNET_FLOW_LOGS,
                        severity="High",
                        resource_name=resource_name,
                        resource_type="google_compute_subnetwork",
                        message="Subnetwork must have flow logging enabled via log_config block for network traffic monitoring",
                        guide="https://cloud.google.com/vpc/docs/flow-logs"
                    )
                )

            # Check private IP Google access
            private_ip_access = resource.get("private_ip_google_access", False)
            if private_ip_access is False:
                violations.append(
                    GCPPolicyViolation(
                        policy_id=GCPPolicyIDs.VPC_SUBNET_PRIVATE_IP_ACCESS,
                        severity="Medium",
                        resource_name=resource_name,
                        resource_type="google_compute_subnetwork",
                        message="Subnetwork should have private_ip_google_access enabled to allow GCP service access without public IPs",
                        guide="https://cloud.google.com/vpc/docs/special-configurations"
                    )
                )

        return violations

    def _check_firewall_rules(self, resources: dict) -> List[GCPPolicyViolation]:
        """
        Validate google_compute_firewall resources.

        Checks:
        - INGRESS rules should not allow 0.0.0.0/0 source ranges
        - SSH (port 22) should not be exposed to 0.0.0.0/0
        - RDP (port 3389) should not be exposed to 0.0.0.0/0
        - FTP (port 21) should not be exposed to 0.0.0.0/0
        """
        violations = []

        if "google_compute_firewall" not in resources:
            return violations

        for resource_name, resource in resources["google_compute_firewall"].items():
            direction = resource.get("direction", "INGRESS")

            # Only check INGRESS rules for public access
            if direction == "INGRESS":
                source_ranges = resource.get("source_ranges", [])

                # Check if rule allows traffic from anywhere
                allows_all_traffic = self._allows_all_sources(source_ranges)

                if allows_all_traffic:
                    # Check what protocols/ports are allowed
                    allows = resource.get("allow", [])
                    denies = resource.get("deny", [])

                    # Process allow rules
                    for allow_rule in allows:
                        protocol = allow_rule.get("protocol", "").lower()
                        ports = allow_rule.get("ports", [])

                        # Check for SSH exposure
                        if self._exposes_port(protocol, ports, 22):
                            violations.append(
                                GCPPolicyViolation(
                                    policy_id=GCPPolicyIDs.VPC_FIREWALL_PREVENT_SSH_ACCESS,
                                    severity="Critical",
                                    resource_name=resource_name,
                                    resource_type="google_compute_firewall",
                                    message="Firewall rule must not allow SSH (port 22) ingress from 0.0.0.0/0 - restricts exposure to specific IPs",
                                    guide="https://cloud.google.com/vpc/docs/firewalls"
                                )
                            )

                        # Check for RDP exposure
                        if self._exposes_port(protocol, ports, 3389):
                            violations.append(
                                GCPPolicyViolation(
                                    policy_id=GCPPolicyIDs.VPC_FIREWALL_RESTRICT_RDP,
                                    severity="Critical",
                                    resource_name=resource_name,
                                    resource_type="google_compute_firewall",
                                    message="Firewall rule must not allow RDP (port 3389) ingress from 0.0.0.0/0 - restricts exposure to specific IPs",
                                    guide="https://cloud.google.com/vpc/docs/firewalls"
                                )
                            )

                        # Check for FTP exposure
                        if self._exposes_port(protocol, ports, 21):
                            violations.append(
                                GCPPolicyViolation(
                                    policy_id=GCPPolicyIDs.VPC_FIREWALL_RESTRICT_FTP,
                                    severity="High",
                                    resource_name=resource_name,
                                    resource_type="google_compute_firewall",
                                    message="Firewall rule must not allow FTP (port 21) ingress from 0.0.0.0/0 - use SFTP instead and restrict to specific IPs",
                                    guide="https://cloud.google.com/vpc/docs/firewalls"
                                )
                            )

                        # Check for unrestricted access to any ports
                        if self._allows_all_ports(protocol, ports):
                            violations.append(
                                GCPPolicyViolation(
                                    policy_id=GCPPolicyIDs.VPC_FIREWALL_UNRESTRICTED_ACCESS,
                                    severity="Critical",
                                    resource_name=resource_name,
                                    resource_type="google_compute_firewall",
                                    message="Firewall rule must specify restricted ports when allowing ingress from 0.0.0.0/0 - limiting to specific ports required",
                                    guide="https://cloud.google.com/vpc/docs/firewalls"
                                )
                            )

        return violations

    def _allows_all_sources(self, source_ranges: list) -> bool:
        """Check if firewall rule allows traffic from 0.0.0.0/0"""
        if not source_ranges:
            return False
        return "0.0.0.0/0" in source_ranges

    def _exposes_port(self, protocol: str, ports: list, target_port: int) -> bool:
        """Check if a specific port is exposed in the firewall rule"""
        # If protocol doesn't match, port is not exposed
        if protocol not in ["tcp", "udp", "all"]:
            return False

        # If no ports specified, it allows all ports
        if not ports or ports is None:
            return True

        # Check if target port is in the ports list
        return str(target_port) in [str(p) for p in ports]

    def _allows_all_ports(self, protocol: str, ports: list) -> bool:
        """Check if firewall rule allows all ports (no port restrictions)"""
        # If protocol is 'all', all ports are allowed
        if protocol == "all":
            return True

        # If ports list is empty, all ports for that protocol are allowed
        if not ports or ports is None:
            return True

        return False

    def create_compliant_examples(self) -> dict:
        """
        Create example compliant VPC resources for testing.

        Returns:
            Dictionary of compliant resources
        """
        return {
            "google_compute_network": {
                "compliant_secure_network": {
                    "name": "compliant-secure-network",
                    "auto_create_subnetworks": False,
                    "routing_mode": "REGIONAL"
                }
            },
            "google_compute_subnetwork": {
                "compliant_secure_subnet": {
                    "name": "compliant-secure-subnet",
                    "ip_cidr_range": "10.0.1.0/24",
                    "network": "compliant_secure_network",
                    "region": "us-central1",
                    "private_ip_google_access": True,
                    "log_config": {
                        "aggregation_interval": "INTERVAL_5_SEC",
                        "flow_sampling": 0.5,
                        "metadata": "INCLUDE_ALL_METADATA"
                    }
                }
            },
            "google_compute_firewall": {
                "compliant_https_only": {
                    "name": "compliant-https-only",
                    "network": "compliant_secure_network",
                    "direction": "INGRESS",
                    "source_ranges": ["203.0.113.0/24"],
                    "allow": [
                        {
                            "protocol": "tcp",
                            "ports": ["443"]
                        }
                    ],
                    "target_tags": ["https-server"]
                },
                "compliant_egress_restricted": {
                    "name": "compliant-egress-restricted",
                    "network": "compliant_secure_network",
                    "direction": "EGRESS",
                    "destination_ranges": ["0.0.0.0/0"],
                    "deny": [
                        {
                            "protocol": "all"
                        }
                    ],
                    "target_tags": ["restricted-outbound"]
                }
            }
        }

    def create_noncompliant_examples(self) -> dict:
        """
        Create example non-compliant VPC resources for testing violations.

        Returns:
            Dictionary of non-compliant resources with security violations
        """
        return {
            "google_compute_network": {
                "noncompliant_auto_subnets": {
                    "name": "noncompliant-auto-subnets",
                    "auto_create_subnetworks": True,
                    "routing_mode": "REGIONAL"
                }
            },
            "google_compute_subnetwork": {
                "noncompliant_no_flow_logs": {
                    "name": "noncompliant-no-flow-logs",
                    "ip_cidr_range": "10.0.2.0/24",
                    "network": "noncompliant_auto_subnets",
                    "region": "us-central1",
                    "private_ip_google_access": False
                    # VIOLATION: No log_config - flow logs disabled
                }
            },
            "google_compute_firewall": {
                "noncompliant_ssh_public": {
                    "name": "noncompliant-ssh-public",
                    "network": "noncompliant_auto_subnets",
                    "direction": "INGRESS",
                    "source_ranges": ["0.0.0.0/0"],
                    "allow": [
                        {
                            "protocol": "tcp",
                            "ports": ["22"]
                        }
                    ]
                    # VIOLATION: SSH exposed to 0.0.0.0/0
                },
                "noncompliant_rdp_public": {
                    "name": "noncompliant-rdp-public",
                    "network": "noncompliant_auto_subnets",
                    "direction": "INGRESS",
                    "source_ranges": ["0.0.0.0/0"],
                    "allow": [
                        {
                            "protocol": "tcp",
                            "ports": ["3389"]
                        }
                    ]
                    # VIOLATION: RDP exposed to 0.0.0.0/0
                },
                "noncompliant_all_ports": {
                    "name": "noncompliant-all-ports",
                    "network": "noncompliant_auto_subnets",
                    "direction": "INGRESS",
                    "source_ranges": ["0.0.0.0/0"],
                    "allow": [
                        {
                            "protocol": "tcp"
                            # VIOLATION: No ports specified = all ports allowed
                        }
                    ]
                },
                "noncompliant_ftp_public": {
                    "name": "noncompliant-ftp-public",
                    "network": "noncompliant_auto_subnets",
                    "direction": "INGRESS",
                    "source_ranges": ["0.0.0.0/0"],
                    "allow": [
                        {
                            "protocol": "tcp",
                            "ports": ["21"]
                        }
                    ]
                    # VIOLATION: FTP exposed to 0.0.0.0/0
                }
            }
        }
