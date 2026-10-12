from typing import Dict, List, Any
from scanner_core.policies.kubernetes.base_checker import BaseSecurityChecker
from scanner_core.models.violation import PolicyViolation
from scanner_core.constants.security_constants import SecurityConstants
from scanner_core.constants.k8s_cve_ids import K8SCVEIDs

class PrivilegedModeChecker(BaseSecurityChecker):
    """K8S-SEC-004: Check for privileged mode in containers"""
    SUPPORTED_KINDS = ["Deployment", "DaemonSet", "Pod"]
    
    def check(self, resources: List[Dict[str, Any]]) -> List[PolicyViolation]:
        """Check privileged mode for all containers"""
        self.violations = []
        
        for resource in resources:
            if not self.should_check_resource(resource, self.SUPPORTED_KINDS):
                continue
            
            self._check_resource(resource)
        
        return self.violations
    
    def _check_resource(self, resource: Dict[str, Any]) -> None:
        """Check a single resource for privileged mode violations"""
        kind = resource.get("kind", "")
        if kind not in ["Deployment", "DaemonSet", "Pod"]:
            return
        
        pod_spec = self.helper.get_pod_spec(resource)
        path_prefix = self.helper.get_path_prefix(kind)
        
        for ctype, idx, container in self.helper.get_containers(pod_spec):
            sec_ctx = self.helper.safe_get(container, "securityContext", default={})
            if sec_ctx.get("privileged") is True:
                container_name = container.get("name", "unknown")
                
                self.add_violation(
                    cve_id=K8SCVEIDs.PRIVILEGED_MODE,
                    severity=SecurityConstants.SEVERITY_HIGH,
                    resource=resource,
                    key_path=f"{path_prefix}.{ctype}[{idx}].securityContext.privileged",
                    message=(
                        f"Container '{container_name}' has privileged mode enabled. "
                        "This poses a significant security risk."
                    ),
                    container_name=container_name,
                    container_type=ctype,
                    container_index=idx
                )