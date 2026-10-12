
from typing import Dict, List, Any
from scanner_core.policies.kubernetes.base_checker import BaseSecurityChecker
from scanner_core.models.violation import PolicyViolation
from scanner_core.constants.security_constants import SecurityConstants
from scanner_core.constants.k8s_cve_ids import K8SCVEIDs

class ProcMountChecker(BaseSecurityChecker):
    """K8S-SEC-012: Check for disallowed /proc mounts"""
    """
    CVE IDs:
        - K8S-SEC-012: Disallowed /proc mounts in containers
    """
    SUPPORTED_KINDS = ["Deployment", "DaemonSet", "Pod"]

    def check(self, resources: List[Dict[str, Any]]) -> List[PolicyViolation]:
        """Check procMount settings for all resources"""
        self.violations = []
        
        for resource in resources:
            if not self.should_check_resource(resource, self.SUPPORTED_KINDS):
                continue
            
            self._check_resource(resource)
        
        return self.violations

    def _check_resource(self, resource: Dict[str, Any]) -> None:
        """Check a single resource for procMount violations"""
        kind = resource.get("kind", "")
        pod_spec = self.helper.get_pod_spec(resource)
        path_prefix = self.helper.get_path_prefix(kind)
        
        for ctype, idx, container in self.helper.get_containers(pod_spec):
            sec_ctx = self.helper.safe_get(container, "securityContext", default={})
            proc_mount = sec_ctx.get("procMount", "Default")
            if proc_mount != "Default":
                container_name = container.get("name", f"container-{idx}")
                
                self.add_violation(
                    cve_id=K8SCVEIDs.DISALLOWED_PROC_MOUNT,
                    severity=SecurityConstants.SEVERITY_HIGH,
                    resource=resource,
                    key_path=f"{path_prefix}.{ctype}[{idx}].securityContext.procMount",
                    message=(
                        f"Container '{container_name}' has disallowed procMount setting '{proc_mount}'. "
                        "Only 'Default' is allowed."
                    )
                )