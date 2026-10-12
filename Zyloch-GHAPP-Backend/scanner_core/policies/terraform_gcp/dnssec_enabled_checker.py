"""
DNSSEC Enabled Checker

This checker validates that Google Cloud DNS managed zones have DNSSEC enabled.
It ensures that 'dnssec_config.state' is set to 'on' for proper DNS security.
"""

from typing import List, Dict, Any
from scanner_core.models.violation import GCPPolicyViolation
from scanner_core.constants.gcp_policy_ids import GCPPolicyIDs


class DnssecEnabledChecker:
    """
    Checks that DNS managed zones have DNSSEC enabled.
    """

    GUIDE = "https://myguide.com"
    POLICY_ID = GCPPolicyIDs.DNSSEC_ENABLED
    REQUIRED_STATE = "on"

    def check(self, resources: Dict[str, Any]) -> List[GCPPolicyViolation]:
        """
        Check DNS managed zones for DNSSEC configuration.

        Args:
            resources: Dictionary containing terraform resources.
                      Expected format: {"google_dns_managed_zone": {"resource_name": {...}}}

        Returns:
            List of violations for zones without DNSSEC enabled.
        """
        violations = []

        dns_zones = resources.get("google_dns_managed_zone", {})

        if not isinstance(dns_zones, dict):
            return violations

        for resource_name, resource in dns_zones.items():
            if not self._has_dnssec_enabled(resource):
                violation = self._create_violation(resource_name)
                violations.append(violation)

        return violations

    def _has_dnssec_enabled(self, resource: Dict[str, Any]) -> bool:
        """
        Check if DNSSEC is enabled in the DNS zone.

        Args:
            resource: DNS managed zone resource configuration

        Returns:
            True if DNSSEC is enabled ('on'), False otherwise.
        """
        if not isinstance(resource, dict):
            return False

        dnssec_config = resource.get("dnssec_config")
        if dnssec_config is None:
            return False

        return self._validate_dnssec_config(dnssec_config)

    def _validate_dnssec_config(self, dnssec_config: Any) -> bool:
        """
        Validate DNSSEC configuration.

        Args:
            dnssec_config: DNSSEC configuration (list or dict)

        Returns:
            True if DNSSEC is enabled, False otherwise.
        """
        # Handle list/array format
        if isinstance(dnssec_config, list):
            if not dnssec_config:
                return False
            # Check if all items have state = 'on'
            for item in dnssec_config:
                if isinstance(item, dict):
                    state = item.get("state")
                    if state != self.REQUIRED_STATE:
                        return False
            return True

        # Handle dict/object format
        if isinstance(dnssec_config, dict):
            state = dnssec_config.get("state")
            return state == self.REQUIRED_STATE

        return False

    def _create_violation(self, resource_name: str) -> GCPPolicyViolation:
        """
        Create a policy violation.

        Args:
            resource_name: Name of the violating resource

        Returns:
            GCPPolicyViolation object
        """
        policy = GCPPolicyIDs.get(self.POLICY_ID)
        message = policy.message if policy else "'dnssec_config.state' must be set to 'on'."
        severity = policy.security_level if policy else "MEDIUM"

        return GCPPolicyViolation(
            policy_id=self.POLICY_ID,
            resource_type="google_dns_managed_zone",
            resource_name=resource_name,
            message=message,
            severity=severity,
            guide=self.GUIDE
        )
