"""
Load Balancer SSL Forwarding Rule Checker

This checker validates that Google Cloud Load Balancer SSL policies
enforce minimum TLS version 1.2 for secure communication. It ensures
'min_tls_version' is set to 'TLS_1_2' for modern SSL/TLS security.
"""

from typing import List, Dict, Any
from scanner_core.models.violation import GCPPolicyViolation
from scanner_core.constants.gcp_policy_ids import GCPPolicyIDs


class LoadbalancerSslForwardingRuleChecker:
    """
    Checks that SSL policies enforce minimum TLS 1.2 version.
    Ensures secure SSL/TLS configurations for load balancers.
    """

    GUIDE = "https://myguide.com"
    POLICY_ID = GCPPolicyIDs.LOADBALANCER_SSL_FORWARDING_RULE
    REQUIRED_MIN_TLS_VERSION = "TLS_1_2"

    def check(self, resources: Dict[str, Any]) -> List[GCPPolicyViolation]:
        """
        Check SSL policies for minimum TLS version configuration.

        Args:
            resources: Dictionary containing terraform resources.
                      Expected format: {"google_compute_ssl_policy": {"resource_name": {...}}}

        Returns:
            List of violations for policies without TLS_1_2 minimum.
        """
        violations = []

        ssl_policies = resources.get("google_compute_ssl_policy", {})

        if not isinstance(ssl_policies, dict):
            return violations

        for resource_name, resource in ssl_policies.items():
            resource_violations = self._validate_ssl_policy(resource, resource_name)
            violations.extend(resource_violations)

        return violations

    def _validate_ssl_policy(self, resource: Dict[str, Any], resource_name: str) -> List[GCPPolicyViolation]:
        """
        Validate a single SSL policy.

        Args:
            resource: The SSL policy resource configuration
            resource_name: Name of the resource

        Returns:
            List of violations found
        """
        violations = []

        # Check if min_tls_version is defined
        min_tls_version = resource.get("min_tls_version")

        if min_tls_version is None:
            violations.append(
                self._create_violation(
                    resource_name,
                    "Attribute 'min_tls_version' must be defined and set to 'TLS_1_2'."
                )
            )
            return violations

        # Check if min_tls_version is set to TLS_1_2
        if min_tls_version != self.REQUIRED_MIN_TLS_VERSION:
            violations.append(
                self._create_violation(
                    resource_name,
                    "Attribute 'min_tls_version' must be set to 'TLS_1_2'."
                )
            )

        return violations

    def _create_violation(self, resource_name: str, message: str) -> GCPPolicyViolation:
        """
        Create a policy violation.

        Args:
            resource_name: Name of the violating resource
            message: Violation message

        Returns:
            GCPPolicyViolation object
        """
        policy = GCPPolicyIDs.get(self.POLICY_ID)
        severity = policy.security_level if policy else "HIGH"

        return GCPPolicyViolation(
            policy_id=self.POLICY_ID,
            resource_type="google_compute_ssl_policy",
            resource_name=resource_name,
            message=message,
            severity=severity,
            guide=self.GUIDE
        )
