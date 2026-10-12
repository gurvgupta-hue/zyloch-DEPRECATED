
from typing import Dict, List, Any
from scanner_core.policies.kubernetes.base_checker import BaseSecurityChecker
from scanner_core.models.violation import PolicyViolation
from scanner_core.constants.security_constants import SecurityConstants
from scanner_core.constants.k8s_cve_ids import K8SCVEIDs

class HostProcessChecker(BaseSecurityChecker):
    """ Check for hostProcess containers"""
    """
        CVE IDs:
        - K8S-SEC-006: HostProcess containers are disallowed in all workloads
    """
    SUPPORTED_KINDS = ["Pod", "Deployment", "DaemonSet"]

    def check(self, resources: List[Dict[str, Any]]) -> List[PolicyViolation]:
        """Check hostProcess setting for all resources"""
        self.violations = []
        
        for resource in resources:
            if not self.should_check_resource(resource, self.SUPPORTED_KINDS):
                continue
            
            self._check_resource(resource)
        
        return self.violations

    def _check_resource(self, resource: Dict[str, Any]) -> None:
        """Check a single resource for hostProcess container violations"""
        kind = resource.get("kind", "")
        pod_spec = self.helper.get_pod_spec(resource)
        path_prefix = self.helper.get_path_prefix(kind)
        
        # Determine CVE ID based on kind
        if kind == "Pod":
            cve_id = K8SCVEIDs.HOST_PROCESS_USAGE
        else:  # Deployment or DaemonSet
            cve_id = K8SCVEIDs.HOST_PROCESS_USAGE
        
        for ctype, idx, container in self.helper.get_containers(pod_spec):
            sec_ctx = self.helper.safe_get(container, "securityContext", default={})
            if sec_ctx.get("hostProcess") is True:
                container_name = container.get("name", f"container-{idx}")
                
                self.add_violation(
                    cve_id=cve_id,
                    severity=SecurityConstants.SEVERITY_HIGH,
                    resource=resource,
                    key_path=f"{path_prefix}.{ctype}[{idx}].securityContext.hostProcess",
                    message=(
                        f"HostProcess containers are disallowed in resource kind {kind}. "
                        f"Container '{container_name}' must not have hostProcess enabled."
                    )
                )