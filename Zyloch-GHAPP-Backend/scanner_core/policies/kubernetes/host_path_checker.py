
from typing import Dict, List, Any
from scanner_core.policies.kubernetes.base_checker import BaseSecurityChecker
from scanner_core.models.violation import PolicyViolation
from scanner_core.constants.security_constants import SecurityConstants
from scanner_core.constants.k8s_cve_ids import K8SCVEIDs

class HostPathChecker(BaseSecurityChecker):
    """K8S-SEC-004: Check for disallowed hostPath volumes"""
    
    SUPPORTED_KINDS = ["Deployment", "DaemonSet"]
    def check(self, resources: List[Dict[str, Any]]) -> List[PolicyViolation]:
        """Check hostNetwork setting for all resources"""
        self.violations = []
        
        for resource in resources:
            if not self.should_check_resource(resource, self.SUPPORTED_KINDS):
                continue
            
            self._check_resource(resource)
        
        return self.violations
    def _check_resource(self, resource: Dict[str, Any]) -> None:
        """Check a single resource for hostPath volume violations"""
        kind = resource.get("kind", "")
        if kind not in ["Deployment", "DaemonSet"]:
            return
        
        # Navigate to volumes in spec.template.spec
        template = self.helper.safe_get(resource, "spec.template", default={})
        spec = self.helper.safe_get(template, "spec", default={})
        volumes = self.helper.safe_get(spec, "volumes", default=[])
        
        # Check each volume for hostPath
        for i, volume in enumerate(volumes):
            volume_hostpath = volume.get("hostPath")
            
            if volume_hostpath is not None:
                self.add_violation(
                    cve_id=K8SCVEIDs.HOST_PATH_VOLUMES,
                    severity="Medium",
                    resource=resource,
                    key_path=f"spec.template.spec.volumes[{i}].hostPath",
                    message=(
                        f"HostPath volumes are forbidden in resource kind {kind}. "
                        f"The field 'spec.template.spec.volumes[{i}].hostPath' must be unset."
                    )
                )
    