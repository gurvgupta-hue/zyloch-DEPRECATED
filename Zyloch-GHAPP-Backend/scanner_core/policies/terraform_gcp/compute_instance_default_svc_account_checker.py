"""
Compute Instance Default Service Account Checker

This checker validates that Google Compute instances do not use overly permissive
service account scopes. It ensures that 'service_account.scopes' does not contain
'cloud-platform' which grants full access to all Google Cloud APIs.
"""

from typing import List, Dict, Any
from scanner_core.models.violation import GCPPolicyViolation
from scanner_core.constants.gcp_policy_ids import GCPPolicyIDs


class ComputeInstanceDefaultSvcAccountChecker:
    """
    Checks that Compute instances do not use overly permissive service account scopes.
    """

    GUIDE = "https://myguide.com"
    POLICY_ID = GCPPolicyIDs.COMPUTE_INSTANCE_DEFAULT_SVC_ACCOUNT
    DISALLOWED_SCOPE = "cloud-platform"

    def check(self, resources: Dict[str, Any]) -> List[GCPPolicyViolation]:
        """
        Check Compute instances for overly permissive service account scopes.

        Args:
            resources: Dictionary containing terraform resources.
                      Expected format: {"google_compute_instance": {"resource_name": {...}}}

        Returns:
            List of violations for instances with 'cloud-platform' scope.
        """
        violations = []

        compute_instances = resources.get("google_compute_instance", {})

        if not isinstance(compute_instances, dict):
            return violations

        for resource_name, resource in compute_instances.items():
            if self._has_disallowed_scope(resource):
                violation = self._create_violation(resource_name)
                violations.append(violation)

        return violations

    def _has_disallowed_scope(self, resource: Dict[str, Any]) -> bool:
        """
        Check if instance has disallowed 'cloud-platform' scope.

        Args:
            resource: Compute instance resource configuration

        Returns:
            True if 'cloud-platform' scope is found, False otherwise.
        """
        if not isinstance(resource, dict):
            return False

        # Check if service_account exists
        service_account = resource.get("service_account")
        if not isinstance(service_account, dict):
            return False

        # Get scopes
        scopes = service_account.get("scopes")
        if scopes is None:
            return False

        # Check if scopes is a list
        if isinstance(scopes, list):
            for scope in scopes:
                if isinstance(scope, str) and self.DISALLOWED_SCOPE in scope:
                    return True
            return False

        # Check if scopes is a string
        if isinstance(scopes, str):
            return self.DISALLOWED_SCOPE in scopes

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
        message = policy.message if policy else "'service_account.scopes' must not contain 'cloud-platform'."
        severity = policy.security_level if policy else "HIGH"

        return GCPPolicyViolation(
            policy_id=self.POLICY_ID,
            resource_type="google_compute_instance",
            resource_name=resource_name,
            message=message,
            severity=severity,
            guide=self.GUIDE
        )
