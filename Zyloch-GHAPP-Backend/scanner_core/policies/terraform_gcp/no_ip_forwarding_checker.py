"""
No IP Forwarding Checker

This checker validates that Google Compute instances do not have IP forwarding
enabled. It ensures 'can_ip_forward' is either undefined or set to false for
proper network security.
"""

from typing import List, Dict, Any
from scanner_core.models.violation import GCPPolicyViolation
from scanner_core.constants.gcp_policy_ids import GCPPolicyIDs


class NoIpForwardingChecker:
    """
    Checks that Compute instances do not enable IP forwarding.
    Ensures secure network configuration without routing capabilities.
    """

    GUIDE = "https://myguide.com"
    POLICY_ID = GCPPolicyIDs.NO_IP_FORWARDING

    def check(self, resources: Dict[str, Any]) -> List[GCPPolicyViolation]:
        """
        Check Compute instances for IP forwarding configuration.

        Args:
            resources: Dictionary containing terraform resources.
                      Expected format: {"google_compute_instance": {"resource_name": {...}}}

        Returns:
            List of violations for instances with IP forwarding enabled.
        """
        violations = []

        compute_instances = resources.get("google_compute_instance", {})

        if not isinstance(compute_instances, dict):
            return violations

        for resource_name, resource in compute_instances.items():
            if self._has_ip_forwarding_enabled(resource):
                violation = self._create_violation(resource_name)
                violations.append(violation)

        return violations

    def _has_ip_forwarding_enabled(self, resource: Dict[str, Any]) -> bool:
        """
        Check if IP forwarding is enabled in the Compute instance.

        Args:
            resource: Compute instance resource configuration

        Returns:
            True if IP forwarding is enabled, False otherwise.
        """
        if not isinstance(resource, dict):
            return False

        # Get can_ip_forward flag
        can_ip_forward = resource.get("can_ip_forward")

        # Check if the value is True (IP forwarding is enabled)
        return can_ip_forward is True

    def _create_violation(self, resource_name: str) -> GCPPolicyViolation:
        """
        Create a policy violation.

        Args:
            resource_name: Name of the violating resource

        Returns:
            GCPPolicyViolation object
        """
        policy = GCPPolicyIDs.get(self.POLICY_ID)
        message = policy.message if policy else "Attribute 'can_ip_forward' must be undefined or set to false."
        severity = policy.security_level if policy else "HIGH"

        return GCPPolicyViolation(
            policy_id=self.POLICY_ID,
            resource_type="google_compute_instance",
            resource_name=resource_name,
            message=message,
            severity=severity,
            guide=self.GUIDE
        )
