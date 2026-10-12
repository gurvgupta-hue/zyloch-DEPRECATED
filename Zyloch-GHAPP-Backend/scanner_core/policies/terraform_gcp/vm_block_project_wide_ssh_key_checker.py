from typing import List
from scanner_core.models.violation import GCPPolicyViolation
from scanner_core.constants.gcp_policy_ids import GCPPolicyIDs


class VmBlockProjectWideSshKeyChecker:
    """Checker for VM Block Project-wide SSH Key security policy (GCP-SEC-006)"""
    
    POLICY_ID = GCPPolicyIDs.VM_BLOCK_PROJECT_WIDE_SSH_KEY
    
    def check(self, resources: dict) -> List[GCPPolicyViolation]:
        """
        Validate that compute instances have block-project-ssh-keys enabled.
        
        Args:
            resources: Dictionary of GCP resources
            
        Returns:
            List of violations found
        """
        violations = []
        
        if "google_compute_instance" not in resources:
            return violations
        
        for resource_name, resource in resources["google_compute_instance"].items():
            # Check if metadata is defined
            metadata = resource.get("metadata")
            if metadata is None:
                violations.append(
                    GCPPolicyViolation(
                        policy_id=self.POLICY_ID,
                        severity="High",
                        resource_name=resource_name,
                        resource_type="google_compute_instance",
                        message="Attribute 'metadata' must be defined.",
                        guide="https://myguide.com"
                    )
                )
                continue
            
            # Check if block-project-ssh-keys is defined
            block_ssh_keys = metadata.get("block-project-ssh-keys")
            if block_ssh_keys is None:
                violations.append(
                    GCPPolicyViolation(
                        policy_id=self.POLICY_ID,
                        severity="High",
                        resource_name=resource_name,
                        resource_type="google_compute_instance",
                        message="Attribute 'metadata[\"block-project-ssh-keys\"]' must be defined and set to true.",
                        guide="https://myguide.com"
                    )
                )
                continue
            
            # Check if block-project-ssh-keys is set to true
            if not self._is_true(block_ssh_keys):
                violations.append(
                    GCPPolicyViolation(
                        policy_id=self.POLICY_ID,
                        severity="High",
                        resource_name=resource_name,
                        resource_type="google_compute_instance",
                        message="Attribute 'metadata[\"block-project-ssh-keys\"]' must be set to true.",
                        guide="https://myguide.com"
                    )
                )
        
        return violations
    
    def _is_true(self, value) -> bool:
        """Check if value is True (boolean or string "true")"""
        if isinstance(value, bool):
            return value is True
        if isinstance(value, str):
            return value.lower() == "true"
        return False
