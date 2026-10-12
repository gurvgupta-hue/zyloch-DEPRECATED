"""
Encryption Key 365-Day Rotation Checker

This checker validates that KMS encryption keys have rotation periods set
to at most 365 days (31536000 seconds). It ensures proper key rotation policies
are in place for cryptographic material.
"""

from typing import List, Dict, Any
from scanner_core.models.violation import GCPPolicyViolation
from scanner_core.constants.gcp_policy_ids import GCPPolicyIDs


class EncryptionKey365RotationChecker:
    """
    Checks that KMS encryption keys have proper rotation periods configured.
    Ensures rotation_period is set and does not exceed 365 days.
    """

    GUIDE = "https://myguide.com"
    POLICY_ID = GCPPolicyIDs.ENCRYPTION_KEY_365_ROTATION
    MAX_ROTATION_SECONDS = 31536000  # 365 days in seconds

    def check(self, resources: Dict[str, Any]) -> List[GCPPolicyViolation]:
        """
        Check KMS crypto keys for proper rotation period configuration.

        Args:
            resources: Dictionary containing terraform resources.
                      Expected format: {"google_kms_crypto_key": {"resource_name": {...}}}

        Returns:
            List of violations for keys with improper rotation periods.
        """
        violations = []

        crypto_keys = resources.get("google_kms_crypto_key", {})

        if not isinstance(crypto_keys, dict):
            return violations

        for resource_name, resource in crypto_keys.items():
            resource_violations = self._validate_key(resource, resource_name)
            violations.extend(resource_violations)

        return violations

    def _validate_key(self, resource: Dict[str, Any], resource_name: str) -> List[GCPPolicyViolation]:
        """
        Validate a single KMS crypto key.

        Args:
            resource: The KMS crypto key configuration
            resource_name: Name of the resource

        Returns:
            List of violations found
        """
        violations = []

        # Check if rotation_period is defined
        rotation_period = resource.get("rotation_period")

        if rotation_period is None:
            violations.append(
                self._create_violation(
                    resource_name,
                    "'rotation_period' must be defined and set to at most '31536000' seconds."
                )
            )
            return violations

        # Parse rotation period (format: "31536000s")
        rotation_seconds = self._parse_rotation_period(rotation_period)

        if rotation_seconds is None:
            violations.append(
                self._create_violation(
                    resource_name,
                    "'rotation_period' must be defined and set to at most '31536000' seconds."
                )
            )
            return violations

        # Check if rotation period exceeds max allowed
        if rotation_seconds > self.MAX_ROTATION_SECONDS:
            violations.append(
                self._create_violation(
                    resource_name,
                    "'rotation_period' must be set to at most '31536000' seconds."
                )
            )

        return violations

    def _parse_rotation_period(self, rotation_period: str) -> int:
        """
        Parse rotation period string and return seconds.

        Expected format: "31536000s" where the last character is a time unit suffix.

        Args:
            rotation_period: Rotation period string (e.g., "31536000s")

        Returns:
            Number of seconds, or None if parsing fails.
        """
        if not isinstance(rotation_period, str):
            return None

        # Remove the time unit suffix (last character)
        if len(rotation_period) == 0:
            return None

        period_value = rotation_period[:-1]  # Remove last character

        try:
            return int(period_value)
        except (ValueError, TypeError):
            return None

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
            resource_type="google_kms_crypto_key",
            resource_name=resource_name,
            message=message,
            severity=severity,
            guide=self.GUIDE
        )
