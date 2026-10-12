"""
Storage Bucket Versioning Checker

This checker validates that Google Storage buckets have versioning enabled.
It ensures that the 'versioning' field is configured and enabled in the bucket resource.
"""

from typing import List, Dict, Any
from scanner_core.models.violation import GCPPolicyViolation
from scanner_core.constants.gcp_policy_ids import GCPPolicyIDs


class StorageBucketVersioningEnabledChecker:
    """
    Checks that Google Storage buckets have versioning enabled.
    """

    GUIDE = "https://myguide.com"
    POLICY_ID = GCPPolicyIDs.STORAGE_BUCKET_VERSIONING_ENABLED

    def check(self, resources: Dict[str, Any]) -> List[GCPPolicyViolation]:
        """
        Check Google Storage buckets for versioning configuration.

        Args:
            resources: Dictionary containing terraform resources.
                      Expected format: {"google_storage_bucket": {"resource_name": {...}}}

        Returns:
            List of violations for buckets without versioning enabled.
        """
        violations = []

        storage_buckets = resources.get("google_storage_bucket", {})

        if not isinstance(storage_buckets, dict):
            return violations

        for resource_name, resource in storage_buckets.items():
            if not self._has_versioning_enabled(resource):
                violation = self._format_violation(resource_name)
                violations.append(violation)

        return violations

    def _has_versioning_enabled(self, resource: Any) -> bool:
        """
        Check if versioning is enabled for the bucket.
        Handles both dict and list formats for versioning field.
        """
        if not isinstance(resource, dict):
            return False
        versioning = resource.get("versioning")
        if isinstance(versioning, dict):
            enabled = versioning.get("enabled")
            return enabled is True
        elif isinstance(versioning, list):
            # Check if any dict in the list has enabled=True
            for v in versioning:
                if isinstance(v, dict) and v.get("enabled") is True:
                    return True
            return False
        else:
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
        message = policy.message if policy else "Versioning must be enabled"
        severity = policy.security_level if policy else "HIGH"

        return GCPPolicyViolation(
            policy_id=self.POLICY_ID,
            resource_type="google_storage_bucket",
            resource_name=resource_name,
            message=message,
            severity=severity,
            guide=self.GUIDE
        )
