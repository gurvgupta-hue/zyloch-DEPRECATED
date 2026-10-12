"""
Storage Bucket Public Access Prevention Checker

This checker validates that Google Storage buckets have public access prevention enforced.
It ensures that the 'public_access_prevention' field is configured and set to 'enforced'.
"""

from typing import List, Dict, Any
from scanner_core.models.violation import GCPPolicyViolation
from scanner_core.constants.gcp_policy_ids import GCPPolicyIDs


class StorageBucketPublicAccessPreventionChecker:
    """
    Checks that Google Storage buckets have public access prevention enforced.
    """

    GUIDE = "https://myguide.com"
    POLICY_ID = GCPPolicyIDs.STORAGE_BUCKET_PUBLIC_ACCESS_PREVENTION

    def check(self, resources: Dict[str, Any]) -> List[GCPPolicyViolation]:
        """
        Check Google Storage buckets for public access prevention configuration.

        Args:
            resources: Dictionary containing terraform resources.
                      Expected format: {"google_storage_bucket": {"resource_name": {...}}}

        Returns:
            List of violations for buckets without public access prevention enforced.
        """
        violations = []

        storage_buckets = resources.get("google_storage_bucket", {})

        if not isinstance(storage_buckets, dict):
            return violations

        for resource_name, resource in storage_buckets.items():
            if not self._has_public_access_prevention_enforced(resource):
                violation = self._format_violation(resource_name)
                violations.append(violation)

        return violations

    def _has_public_access_prevention_enforced(self, resource: Any) -> bool:
        """
        Check if public access prevention is enforced for the bucket.

        Args:
            resource: Storage bucket resource configuration

        Returns:
            True if public access prevention is enforced, False otherwise.
        """
        if not isinstance(resource, dict):
            return False

        # Check if public_access_prevention field exists
        pap = resource.get("public_access_prevention")

        # tfplan.json format: plain string (e.g. "enforced", "disabled")
        if isinstance(pap, str):
            return pap.lower() == "enforced"

        # Legacy/test format: dict with "enabled" key
        if isinstance(pap, dict):
            return pap.get("enabled") == "enforced"

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
        message = policy.message if policy else "Public access prevention must be enforced"
        severity = policy.security_level if policy else "HIGH"

        return GCPPolicyViolation(
            policy_id=self.POLICY_ID,
            resource_type="google_storage_bucket",
            resource_name=resource_name,
            message=message,
            severity=severity,
            guide=self.GUIDE
        )
