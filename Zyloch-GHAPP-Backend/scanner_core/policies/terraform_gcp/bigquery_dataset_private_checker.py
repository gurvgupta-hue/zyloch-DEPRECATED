"""
BigQuery Dataset Private Access Checker

This checker validates that BigQuery datasets are not publicly accessible.
It ensures that 'access.special_group' is not set to 'allAuthenticatedUsers'.
"""

from typing import List, Dict, Any
from scanner_core.models.violation import GCPPolicyViolation
from scanner_core.constants.gcp_policy_ids import GCPPolicyIDs


class BigQueryDatasetPrivateChecker:
    """
    Checks that BigQuery datasets do not allow public access through allAuthenticatedUsers.
    """

    GUIDE = "https://myguide.com"
    POLICY_ID = GCPPolicyIDs.BIGQUERY_DATASET_PRIVATE

    def check(self, resources: Dict[str, Any]) -> List[GCPPolicyViolation]:
        """
        Check BigQuery datasets for public access violations.

        Args:
            resources: Dictionary containing terraform resources.
                      Expected format: {"google_bigquery_dataset": {"resource_name": {...}}}

        Returns:
            List of violation messages for datasets with public access.
        """
        violations = []

        bigquery_datasets = resources.get("google_bigquery_dataset", {})

        if not isinstance(bigquery_datasets, dict):
            return violations

        for resource_name, resource in bigquery_datasets.items():
            if self._is_publicly_accessible(resource.get("access")):
                violation = self._format_violation(resource_name)
                violations.append(violation)

        return violations

    def _is_publicly_accessible(self, access: Any) -> bool:
        """
        Check if access configuration allows public access.

        Args:
            access: Access configuration (can be a dict, list, or None)

        Returns:
            True if the access allows allAuthenticatedUsers, False otherwise.
        """
        if access is None:
            return False

        # Handle dict/object access
        if isinstance(access, dict):
            if access.get("special_group") == "allAuthenticatedUsers":
                return True

        # Handle list/array access
        if isinstance(access, list):
            for item in access:
                if isinstance(item, dict) and item.get("special_group") == "allAuthenticatedUsers":
                    return True

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
        message = policy.message if policy else "Unknown policy violation"
        severity = policy.security_level if policy else "HIGH"

        return GCPPolicyViolation(
            policy_id=self.POLICY_ID,
            resource_type="google_bigquery_dataset",
            resource_name=resource_name,
            message=message,
            severity=severity,
            guide=self.GUIDE
        )
