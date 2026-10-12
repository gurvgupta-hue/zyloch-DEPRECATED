from typing import List
from scanner_core.models.violation import GCPPolicyViolation
from scanner_core.constants.gcp_policy_ids import GCPPolicyIDs


class ProjectOsLoginChecker:
    """Checker for Project OS Login security policy (GCP-SEC-015)"""
    
    POLICY_ID = GCPPolicyIDs.PROJECT_OS_LOGIN
    
    def check(self, resources: dict) -> List[GCPPolicyViolation]:
        """
        Validate that OS Login is enabled in project metadata.
        
        Args:
            resources: Dictionary of GCP resources
            
        Returns:
            List of violations found
        """
        violations = []
        
        if "google_compute_project_metadata" not in resources:
            return violations
        
        for resource_name, resource in resources["google_compute_project_metadata"].items():
            metadata = resource.get("metadata", {})
            
            if not self._has_os_login_enabled(metadata):
                violations.append(
                    GCPPolicyViolation(
                        policy_id=self.POLICY_ID,
                        severity="High",
                        resource_name=resource_name,
                        resource_type="google_compute_project_metadata",
                        message="Attribute metadata['enable-oslogin'] must be defined and set to true.",
                        guide="https://myguide.com"
                    )
                )
            elif self._is_os_login_disabled(metadata):
                violations.append(
                    GCPPolicyViolation(
                        policy_id=self.POLICY_ID,
                        severity="High",
                        resource_name=resource_name,
                        resource_type="google_compute_project_metadata",
                        message="Attribute metadata['enable-oslogin'] must be set to true.",
                        guide="https://myguide.com"
                    )
                )
        
        return violations
    
    def _is_os_login_disabled(self, metadata: dict) -> bool:
        """Check if enable-oslogin is explicitly set to False"""
        return metadata.get("enable-oslogin") is False
    
    def _has_os_login_enabled(self, metadata: dict) -> bool:
        """Check if enable-oslogin is defined and set to true"""
        enable_oslogin = metadata.get("enable-oslogin")
        if enable_oslogin is None:
            return False
        return enable_oslogin is True
