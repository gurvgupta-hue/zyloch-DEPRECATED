"""
Storage Bucket Logging Checker

This checker validates that Google Storage buckets have logging enabled.
It ensures that 'logging' field is configured in the bucket resource.
"""

from typing import List, Dict, Any
from scanner_core.models.violation import GCPPolicyViolation
from scanner_core.constants.gcp_policy_ids import GCPPolicyIDs


class BucketLoggingEnabledChecker:
    """
    Checks that Google Storage buckets have logging enabled.
    """

    GUIDE = "https://myguide.com"
    POLICY_ID = GCPPolicyIDs.BUCKET_LOGGING_ENABLED

    def check(self, resources: Dict[str, Any]) -> List[GCPPolicyViolation]:
        """
        Check Google Storage buckets for logging configuration.

        Args:
            resources: Dictionary containing terraform resources.
                      Expected format: {"google_storage_bucket": {"resource_name": {...}}}

        Returns:
            List of violations for buckets without logging enabled.
        """
        violations = []

        storage_buckets = resources.get("google_storage_bucket", {})

        if not isinstance(storage_buckets, dict):
            return violations

        for resource_name, resource in storage_buckets.items():
            if not self._has_logging_enabled(resource):
                violation = self._format_violation(resource_name)
                violations.append(violation)

        return violations

    def _has_logging_enabled(self, resource: Any) -> bool:
        """
        Check if logging is configured for the bucket.

        Args:
            resource: Storage bucket resource configuration

        Returns:
            True if logging is enabled, False otherwise.
        """
        if not isinstance(resource, dict):
            return False

        # Check if logging field exists and is not empty/None
        logging_config = resource.get("logging")

        # tfplan.json format: list of dicts (e.g. [{"log_bucket": "..."}])
        if isinstance(logging_config, list):
            return len(logging_config) > 0 and any(
                isinstance(entry, dict) and len(entry) > 0
                for entry in logging_config
            )

        # Legacy/test format: dict
        if isinstance(logging_config, dict):
            return len(logging_config) > 0

        return False

    def _format_violation(self, resource_name: str) -> GCPPolicyViolation:
        """
        Format violation message.

        Args:
            resource_name: Name of the resource with the violation.

        Returns:
            GCPPolicyViolation object containing violation details.
        """
        policy = GCPPolicyIDs.get(self.POLICY_ID)
        message = policy.message if policy else "Logging must be enabled"
        severity = policy.security_level if policy else "MEDIUM"

        return GCPPolicyViolation(
            policy_id=self.POLICY_ID,
            resource_type="google_storage_bucket",
            resource_name=resource_name,
            message=message,
            severity=severity,
            guide=self.GUIDE
        )
