from typing import List
from scanner_core.models.violation import GCPPolicyViolation
from scanner_core.constants.gcp_policy_ids import GCPPolicyIDs


class StorageBucketNoPublicChecker:
    """Checker for Storage Bucket Public Access security policy (GCP-SEC-003)"""
    
    POLICY_ID = GCPPolicyIDs.STORAGE_BUCKET_NO_PUBLIC
    
    def check(self, resources: dict) -> List[GCPPolicyViolation]:
        """
        Validate that storage bucket IAM bindings do not grant public access.
        
        Args:
            resources: Dictionary of GCP resources
            
        Returns:
            List of violations found
        """
        violations = []
        
        if "google_storage_bucket_iam_binding" not in resources:
            return violations
        
        for resource_name, resource in resources["google_storage_bucket_iam_binding"].items():
            members = resource.get("members", [])
            
            # Check if members is empty or not defined
            if not members:
                violations.append(
                    GCPPolicyViolation(
                        policy_id=self.POLICY_ID,
                        severity="High",
                        resource_name=resource_name,
                        resource_type="google_storage_bucket_iam_binding",
                        message="Attribute 'members' must be defined and not null.",
                        guide="https://myguide.com"
                    )
                )
                continue
            
            # Check for public access principals
            for member in members:
                if self._is_public_member(member):
                    public_group = "allUsers" if "allUsers" in member else "allAuthenticatedUsers"
                    violations.append(
                        GCPPolicyViolation(
                            policy_id=self.POLICY_ID,
                            severity="Critical",
                            resource_name=resource_name,
                            resource_type="google_storage_bucket_iam_binding",
                            message=f"Attribute 'members' must not have '{public_group}' defined.",
                            guide="https://myguide.com"
                        )
                    )
        
        return violations
    
    def _is_public_member(self, member: str) -> bool:
        """Check if member grants public access"""
        return "allUsers" in member or "allAuthenticatedUsers" in member
