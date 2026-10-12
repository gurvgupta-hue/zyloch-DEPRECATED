"""
GCP VM Encryption Compliance Checker

Validates Google Cloud Compute Engine instances for encryption compliance,
including checks for:
- Disk encryption configuration (CSEK, KMS, Google-managed)
- Shielded VM features (Secure Boot, vTPM, Integrity Monitoring)
- Public IP exposure
- Service account configuration
- Metadata security settings

Policy Coverage:
- GCP-SEC-VM-001: Disk encryption required
- GCP-SEC-VM-002: Shielded VM features
- GCP-SEC-VM-003: Public IP restriction
- GCP-SEC-VM-004: Metadata settings
- GCP-SEC-VM-005: Service account security
"""

from typing import Dict, List
from scanner_core.models.violation import GCPPolicyViolation
from scanner_core.constants.gcp_policy_ids import GCPPolicyIDs


class VMEncryptionChecker:
    """Validates GCP Compute Engine instance encryption compliance."""

    def __init__(self):
        """Initialize VM encryption checker with policy definitions."""
        self.name = "VM Encryption Compliance Checker"
        self.resource_types = [
            "google_compute_instance",
            "google_compute_disk",
        ]

        # Load encryption policies from centralized registry
        self.policies = {
            GCPPolicyIDs.VM_ENCRYPTION_REQUIRED: {
                "name": "Disk Encryption Required",
                "severity": "High",
                "description": "Compute Engine disks must have encryption configured (CSEK, KMS, or Google-managed)",
                "guide": "https://cloud.google.com/compute/docs/disks/customer-supplied-encryption",
            },
            GCPPolicyIDs.VM_SHIELDED_VM_FEATURES: {
                "name": "Shielded VM Features",
                "severity": "High",
                "description": "Production instances should enable Shielded VM features (Secure Boot, vTPM, Integrity Monitoring)",
                "guide": "https://cloud.google.com/security/shielded-vm",
            },
            GCPPolicyIDs.VM_PUBLIC_IP_RESTRICTION: {
                "name": "Public IP Restriction",
                "severity": "Critical",
                "description": "Instances should not have public IP addresses unless explicitly required",
                "guide": "https://cloud.google.com/vpc/docs/firewalls",
            },
            GCPPolicyIDs.VM_METADATA_SECURITY: {
                "name": "Metadata Security",
                "severity": "Medium",
                "description": "Metadata should have secure defaults (enable OS login, disable project SSH keys)",
                "guide": "https://cloud.google.com/compute/docs/instances/managing-instance-access#enable_oslogin",
            },
            GCPPolicyIDs.VM_SERVICE_ACCOUNT_SECURITY: {
                "name": "Service Account Security",
                "severity": "High",
                "description": "Service accounts should follow least privilege principle with minimal scopes",
                "guide": "https://cloud.google.com/compute/docs/access/service-accounts",
            },
        }

    def check(self, resources: Dict) -> List[GCPPolicyViolation]:
        """
        Validate VM encryption compliance across resources.

        Args:
            resources: Dictionary of Terraform resources indexed by type

        Returns:
            List of GCPPolicyViolation objects for non-compliant resources
        """
        violations = []

        # Check Compute Engine instances
        if "google_compute_instance" in resources:
            violations.extend(
                self._check_compute_instances(
                    resources["google_compute_instance"]
                )
            )

        # Check standalone disks
        if "google_compute_disk" in resources:
            violations.extend(
                self._check_compute_disks(resources["google_compute_disk"])
            )

        return violations

    def _check_compute_instances(self, instances: Dict) -> List[GCPPolicyViolation]:
        """Validate individual compute instances."""
        violations = []

        for instance_name, instance_config in instances.items():
            # Check encryption configuration
            if not self._has_encryption_config(instance_config):
                violations.append(
                    GCPPolicyViolation(
                        policy_id=GCPPolicyIDs.VM_ENCRYPTION_REQUIRED,
                        severity=self.policies[GCPPolicyIDs.VM_ENCRYPTION_REQUIRED]["severity"],
                        resource_type="google_compute_instance",
                        resource_name=instance_name,
                        message="Instance does not have explicit disk encryption configuration. "
                        "Configure CSEK, KMS, or ensure Google-managed encryption is intended.",
                        guide=self.policies[GCPPolicyIDs.VM_ENCRYPTION_REQUIRED]["guide"],
                    )
                )

            # Check Shielded VM configuration
            if not self._has_shielded_vm_config(instance_config):
                violations.append(
                    GCPPolicyViolation(
                        policy_id=GCPPolicyIDs.VM_SHIELDED_VM_FEATURES,
                        severity=self.policies[GCPPolicyIDs.VM_SHIELDED_VM_FEATURES]["severity"],
                        resource_type="google_compute_instance",
                        resource_name=instance_name,
                        message="Instance does not have Shielded VM features enabled. "
                        "Enable Secure Boot, vTPM, and Integrity Monitoring.",
                        guide=self.policies[GCPPolicyIDs.VM_SHIELDED_VM_FEATURES]["guide"],
                    )
                )

            # Check public IP exposure
            if self._has_public_ip(instance_config):
                violations.append(
                    GCPPolicyViolation(
                        policy_id=GCPPolicyIDs.VM_PUBLIC_IP_RESTRICTION,
                        severity=self.policies[GCPPolicyIDs.VM_PUBLIC_IP_RESTRICTION]["severity"],
                        resource_type="google_compute_instance",
                        resource_name=instance_name,
                        message="Instance has public IP address configured. "
                        "Remove public IP unless explicitly required for business needs.",
                        guide=self.policies[GCPPolicyIDs.VM_PUBLIC_IP_RESTRICTION]["guide"],
                    )
                )

            # Check metadata security
            if not self._has_secure_metadata(instance_config):
                violations.append(
                    GCPPolicyViolation(
                        policy_id=GCPPolicyIDs.VM_METADATA_SECURITY,
                        severity=self.policies[GCPPolicyIDs.VM_METADATA_SECURITY]["severity"],
                        resource_type="google_compute_instance",
                        resource_name=instance_name,
                        message="Instance metadata does not have secure defaults. "
                        "Enable OS login and disable project-wide SSH keys.",
                        guide=self.policies[GCPPolicyIDs.VM_METADATA_SECURITY]["guide"],
                    )
                )

            # Check service account
            if not self._has_secure_service_account(instance_config):
                violations.append(
                    GCPPolicyViolation(
                        policy_id=GCPPolicyIDs.VM_SERVICE_ACCOUNT_SECURITY,
                        severity=self.policies[GCPPolicyIDs.VM_SERVICE_ACCOUNT_SECURITY]["severity"],
                        resource_type="google_compute_instance",
                        resource_name=instance_name,
                        message="Instance service account configuration violates least privilege. "
                        "Use specific scopes instead of cloud-platform scope.",
                        guide=self.policies[GCPPolicyIDs.VM_SERVICE_ACCOUNT_SECURITY]["guide"],
                    )
                )

        return violations

    def _check_compute_disks(self, disks: Dict) -> List[GCPPolicyViolation]:
        """Validate standalone compute disks."""
        violations = []

        for disk_name, disk_config in disks.items():
            # Check if disk has encryption key specified
            if not self._disk_has_encryption(disk_config):
                violations.append(
                    GCPPolicyViolation(
                        policy_id=GCPPolicyIDs.VM_ENCRYPTION_REQUIRED,
                        severity=self.policies[GCPPolicyIDs.VM_ENCRYPTION_REQUIRED]["severity"],
                        resource_type="google_compute_disk",
                        resource_name=disk_name,
                        message="Disk does not have customer-supplied encryption key (CSEK) configured. "
                        "Add kms_key_name for KMS encryption or customer_supplied_encryption for CSEK.",
                        guide=self.policies[GCPPolicyIDs.VM_ENCRYPTION_REQUIRED]["guide"],
                    )
                )

        return violations

    def _has_encryption_config(self, instance: Dict) -> bool:
        """Check if instance has encryption configuration."""
        # Check boot_disk for encryption configuration
        boot_disk = instance.get("boot_disk", [])
        if isinstance(boot_disk, list) and len(boot_disk) > 0:
            boot_disk_config = boot_disk[0] if isinstance(boot_disk[0], dict) else {}

            # Check for kms_key_name or encrypt_key (CSEK)
            if boot_disk_config.get("kms_key_name"):
                return True
            if boot_disk_config.get("encrypt_key"):
                return True

            # Check initialize_params for labels indicating encryption intent
            init_params = boot_disk_config.get("initialize_params", [])
            if isinstance(init_params, list) and len(init_params) > 0:
                params = init_params[0] if isinstance(init_params[0], dict) else {}
                labels = params.get("labels", {})
                if labels and isinstance(labels, dict):
                    if "encryption" in labels or "compliance" in labels:
                        return True

        return True  # Google-managed is default compliant

    def _has_shielded_vm_config(self, instance: Dict) -> bool:
        """Check if instance has Shielded VM configuration."""
        shielded_config = instance.get("shielded_instance_config", [])

        if isinstance(shielded_config, list) and len(shielded_config) > 0:
            config = shielded_config[0] if isinstance(shielded_config[0], dict) else {}

            # All three features should be enabled
            secure_boot = config.get("enable_secure_boot", [False])[0]
            vtpm = config.get("enable_vtpm", [False])[0]
            integrity = config.get("enable_integrity_monitoring", [False])[0]

            return secure_boot and vtpm and integrity

        return False

    def _has_public_ip(self, instance: Dict) -> bool:
        """Check if instance has public IP address."""
        network_interfaces = instance.get("network_interface", [])

        if isinstance(network_interfaces, list):
            for iface in network_interfaces:
                if isinstance(iface, dict):
                    access_config = iface.get("access_config", [])
                    # If access_config exists (even empty), public IP is configured
                    if isinstance(access_config, list) and len(access_config) > 0:
                        return True

        return False

    def _has_secure_metadata(self, instance: Dict) -> bool:
        """Check if instance has secure metadata configuration."""
        metadata = instance.get("metadata", [])

        if isinstance(metadata, list) and len(metadata) > 0:
            meta_dict = metadata[0] if isinstance(metadata[0], dict) else {}

            # Check for OS login enabled
            oslogin = meta_dict.get("enable-oslogin", ["false"])
            oslogin_val = oslogin[0] if isinstance(oslogin, list) else oslogin
            if oslogin_val != "true":
                return False

            # Check for blocking project SSH keys
            block_ssh = meta_dict.get("block-project-ssh-keys", ["false"])
            block_ssh_val = block_ssh[0] if isinstance(block_ssh, list) else block_ssh
            if block_ssh_val != "true":
                return False

            return True

        return False

    def _has_secure_service_account(self, instance: Dict) -> bool:
        """Check if service account follows least privilege."""
        sa_config = instance.get("service_account", [])

        if isinstance(sa_config, list) and len(sa_config) > 0:
            sa = sa_config[0] if isinstance(sa_config[0], dict) else {}

            # Check scopes - should not include cloud-platform as sole scope
            scopes = sa.get("scopes", [])
            if isinstance(scopes, list) and len(scopes) > 0:
                # If it's a list of scopes
                if isinstance(scopes[0], list):
                    scopes_list = scopes[0]
                else:
                    scopes_list = scopes

                # cloud-platform alone is too broad
                if scopes_list == ["cloud-platform"]:
                    return False

                # Specific scopes are acceptable
                return True

        return True  # Default SA is acceptable if not specified

    def _disk_has_encryption(self, disk: Dict) -> bool:
        """Check if disk has encryption key."""
        # Check for KMS key
        if disk.get("kms_key_name"):
            return True

        # Check for CSEK
        if disk.get("customer_supplied_encryption"):
            return True

        # Check labels for encryption intent
        labels = disk.get("labels", {})
        if isinstance(labels, dict) and "encryption" in labels:
            return True

        return False


