"""
GKE Legacy Authorization Disabled Checker

This checker validates that Google Kubernetes Engine (GKE) clusters do not use
legacy ABAC (Attribute-Based Access Control). It ensures 'enable_legacy_abac'
is set to false for modern RBAC security practices.
"""

from typing import List, Dict, Any
from scanner_core.models.violation import GCPPolicyViolation
from scanner_core.constants.gcp_policy_ids import GCPPolicyIDs


class GkeLegacyAuthorizationDisabledChecker:
    """
    Checks that GKE clusters do not enable legacy ABAC authorization.
    Ensures modern RBAC is used instead for better security.
    """

    GUIDE = "https://myguide.com"
    POLICY_ID = GCPPolicyIDs.GKE_LEGACY_AUTHORIZATION_DISABLED

    def check(self, resources: Dict[str, Any]) -> List[GCPPolicyViolation]:
        """
        Check GKE clusters for legacy ABAC enablement.

        Args:
            resources: Dictionary containing terraform resources.
                      Expected format: {"google_container_cluster": {"resource_name": {...}}}

        Returns:
            List of violations for clusters with legacy ABAC enabled.
        """
        violations = []

        container_clusters = resources.get("google_container_cluster", {})

        if not isinstance(container_clusters, dict):
            return violations

        for resource_name, resource in container_clusters.items():
            if self._has_legacy_abac_enabled(resource):
                violation = self._create_violation(resource_name)
                violations.append(violation)

        return violations

    def _has_legacy_abac_enabled(self, resource: Dict[str, Any]) -> bool:
        """
        Check if legacy ABAC is enabled in the GKE cluster.

        Args:
            resource: GKE cluster resource configuration

        Returns:
            True if legacy ABAC is enabled, False otherwise.
        """
        if not isinstance(resource, dict):
            return False

        # Get enable_legacy_abac flag
        enable_legacy_abac = resource.get("enable_legacy_abac")

        # Check if the value is True (legacy ABAC is enabled)
        return enable_legacy_abac is True

    def _create_violation(self, resource_name: str) -> GCPPolicyViolation:
        """
        Create a policy violation.

        Args:
            resource_name: Name of the violating resource

        Returns:
            GCPPolicyViolation object
        """
        policy = GCPPolicyIDs.get(self.POLICY_ID)
        message = policy.message if policy else "Attribute 'enable_legacy_abac' must be set to false."
        severity = policy.security_level if policy else "HIGH"

        return GCPPolicyViolation(
            policy_id=self.POLICY_ID,
            resource_type="google_container_cluster",
            resource_name=resource_name,
            message=message,
            severity=severity,
            guide=self.GUIDE
        )
