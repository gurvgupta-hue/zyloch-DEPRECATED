"""
Google Cloud Load Balancer Security Compliance Checker

Validates Google Cloud Load Balancer (GCLB) resources for security compliance,
including checks for:
- Minimum TLS version enforcement (TLS 1.2+)
- Cipher suite strength (no COMPATIBLE profile)
- Cloud CDN enablement
- Cloud Armor security policy attachment

Policy Coverage:
- GCP-SEC-LB-001: Minimum TLS version (TLS 1.2+)
- GCP-SEC-LB-002: Cipher suite strength (modern/restricted profile)
- GCP-SEC-LB-003: Cloud CDN enabled
- GCP-SEC-LB-004: Cloud Armor security policy attached
"""

from typing import Dict, List
from scanner_core.models.violation import GCPPolicyViolation
from scanner_core.constants.gcp_policy_ids import GCPPolicyIDs


class LoadBalancerSecurityChecker:
    """Validates Google Cloud Load Balancer security compliance."""

    def __init__(self):
        """Initialize Load Balancer security checker with policy definitions."""
        self.name = "Load Balancer Security Compliance Checker"
        self.resource_types = [
            "google_compute_ssl_policy",
            "google_compute_backend_service",
            "google_compute_target_https_proxy",
            "google_compute_global_forwarding_rule",
        ]

        # Load LB policies from centralized registry
        self.policies = {
            GCPPolicyIDs.LOADBALANCER_SSL_FORWARDING_RULE: {
                "name": "Minimum TLS Version",
                "severity": "High",
                "description": "SSL policy must enforce minimum TLS version 1.2 or higher",
                "guide": "https://cloud.google.com/load-balancing/docs/ssl-policies-concepts",
            },
            GCPPolicyIDs.LB_CIPHER_SUITE_STRENGTH: {
                "name": "Cipher Suite Strength",
                "severity": "High",
                "description": "SSL policy must use MODERN or RESTRICTED profile (no COMPATIBLE)",
                "guide": "https://cloud.google.com/load-balancing/docs/ssl-policies-concepts",
            },
            GCPPolicyIDs.LB_CDN_ENABLED: {
                "name": "Cloud CDN Enabled",
                "severity": "Medium",
                "description": "Backend service should have Cloud CDN enabled for performance",
                "guide": "https://cloud.google.com/cdn/docs/caching-best-practices",
            },
            GCPPolicyIDs.LB_SECURITY_POLICY: {
                "name": "Cloud Armor Security Policy",
                "severity": "Critical",
                "description": "Backend service must be protected by Cloud Armor security policy",
                "guide": "https://cloud.google.com/armor/docs/quickstart",
            },
        }

    def check(self, resources: Dict) -> List[GCPPolicyViolation]:
        """
        Validate Load Balancer security compliance across resources.

        Args:
            resources: Dictionary of Terraform resources indexed by type

        Returns:
            List of GCPPolicyViolation objects for non-compliant resources
        """
        violations = []

        # Check SSL policies
        if "google_compute_ssl_policy" in resources:
            violations.extend(
                self._check_ssl_policies(resources["google_compute_ssl_policy"])
            )

        # Check backend services
        if "google_compute_backend_service" in resources:
            violations.extend(
                self._check_backend_services(resources["google_compute_backend_service"])
            )

        return violations

    def _check_ssl_policies(self, policies: Dict) -> List[GCPPolicyViolation]:
        """Validate SSL policies for TLS and cipher suite compliance."""
        violations = []

        for policy_name, policy_config in policies.items():
            # Check minimum TLS version
            if not self._has_secure_tls_version(policy_config):
                violations.append(
                    GCPPolicyViolation(
                        policy_id=GCPPolicyIDs.LOADBALANCER_SSL_FORWARDING_RULE,
                        severity=self.policies[GCPPolicyIDs.LOADBALANCER_SSL_FORWARDING_RULE]["severity"],
                        resource_type="google_compute_ssl_policy",
                        resource_name=policy_name,
                        message="SSL policy enforces minimum TLS version below 1.2. "
                        "Configure minimum TLS version to TLS_1_2 or higher.",
                        guide=self.policies[GCPPolicyIDs.LOADBALANCER_SSL_FORWARDING_RULE]["guide"],
                    )
                )

            # Check cipher suite strength
            if not self._has_strong_cipher_suite(policy_config):
                violations.append(
                    GCPPolicyViolation(
                        policy_id=GCPPolicyIDs.LB_CIPHER_SUITE_STRENGTH,
                        severity=self.policies[GCPPolicyIDs.LB_CIPHER_SUITE_STRENGTH]["severity"],
                        resource_type="google_compute_ssl_policy",
                        resource_name=policy_name,
                        message="SSL policy uses COMPATIBLE profile allowing weak ciphers. "
                        "Use MODERN or RESTRICTED profile instead.",
                        guide=self.policies[GCPPolicyIDs.LB_CIPHER_SUITE_STRENGTH]["guide"],
                    )
                )

        return violations

    def _check_backend_services(self, services: Dict) -> List[GCPPolicyViolation]:
        """Validate backend services for CDN and security policy."""
        violations = []

        for service_name, service_config in services.items():
            # Check CDN enabled
            if not self._has_cdn_enabled(service_config):
                violations.append(
                    GCPPolicyViolation(
                        policy_id=GCPPolicyIDs.LB_CDN_ENABLED,
                        severity=self.policies[GCPPolicyIDs.LB_CDN_ENABLED]["severity"],
                        resource_type="google_compute_backend_service",
                        resource_name=service_name,
                        message="Backend service does not have Cloud CDN enabled. "
                        "Enable CDN for improved performance and caching.",
                        guide=self.policies[GCPPolicyIDs.LB_CDN_ENABLED]["guide"],
                    )
                )

            # Check security policy
            if not self._has_security_policy(service_config):
                violations.append(
                    GCPPolicyViolation(
                        policy_id=GCPPolicyIDs.LB_SECURITY_POLICY,
                        severity=self.policies[GCPPolicyIDs.LB_SECURITY_POLICY]["severity"],
                        resource_type="google_compute_backend_service",
                        resource_name=service_name,
                        message="Backend service is not protected by Cloud Armor security policy. "
                        "Attach a security policy to protect against DDoS and WAF threats.",
                        guide=self.policies[GCPPolicyIDs.LB_SECURITY_POLICY]["guide"],
                    )
                )

        return violations

    def _has_secure_tls_version(self, policy: Dict) -> bool:
        """Check if SSL policy enforces TLS 1.2 or higher."""
        min_tls = policy.get("min_tls_version")

        if isinstance(min_tls, list) and len(min_tls) > 0:
            min_tls = min_tls[0]

        if not min_tls:
            return False

        # TLS_1_2 or higher is compliant
        return min_tls in ["TLS_1_2"]

    def _has_strong_cipher_suite(self, policy: Dict) -> bool:
        """Check if SSL policy uses strong cipher profiles."""
        profile = policy.get("profile")

        if isinstance(profile, list) and len(profile) > 0:
            profile = profile[0]

        if not profile:
            return False

        # MODERN and RESTRICTED are compliant
        # COMPATIBLE is weak (allows legacy ciphers)
        return profile in ["MODERN", "RESTRICTED"]

    def _has_cdn_enabled(self, service: Dict) -> bool:
        """Check if backend service has CDN enabled."""
        enable_cdn = service.get("enable_cdn")

        if isinstance(enable_cdn, list) and len(enable_cdn) > 0:
            enable_cdn = enable_cdn[0]

        return bool(enable_cdn)

    def _has_security_policy(self, service: Dict) -> bool:
        """Check if backend service has security policy attached."""
        security_policy = service.get("security_policy")

        if isinstance(security_policy, list) and len(security_policy) > 0:
            security_policy = security_policy[0]

        return bool(security_policy)
