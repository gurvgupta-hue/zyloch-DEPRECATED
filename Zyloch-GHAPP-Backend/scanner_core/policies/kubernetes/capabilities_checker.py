from typing import Dict, List, Any
from scanner_core.policies.kubernetes.base_checker import BaseSecurityChecker
from scanner_core.models.violation import PolicyViolation
from scanner_core.constants.security_constants import SecurityConstants
from scanner_core.constants.k8s_cve_ids import K8SCVEIDs

class CapabilitiesChecker(BaseSecurityChecker):
    """ Checks for disallowed capabilities in container security contexts """
    SUPPORTED_KINDS = ["Deployment", "DaemonSet", "Pod"]
    
    def check(self, resources: List[Dict[str, Any]]) -> List[PolicyViolation]:
        """Check imagePullPolicy for all containers"""
        self.violations = []
        
        for resource in resources:
            if not self.should_check_resource(resource, self.SUPPORTED_KINDS):
                continue
            
            self.check_capabilities(resource)
        
        return self.violations

    def check_capabilities(self, resource: Dict[str, Any]) -> None:
        """K8S-SEC-002: Check for disallowed capabilities"""
        
        kind = resource.get("kind", "")
        if kind not in ["Deployment", "DaemonSet", "Pod"]:
            return
        
        pod_spec = self.helper.get_pod_spec(resource)
        path_prefix = self.helper.get_path_prefix(kind)
        
        for ctype, idx, container in self.helper.get_containers(pod_spec):
            sec_ctx = self.helper.safe_get(container, "securityContext", default={})
            capabilities = self.helper.safe_get(sec_ctx, "capabilities", default={})
            caps_add = set(self.helper.safe_get(capabilities, "add", default=[]))
            
            disallowed = caps_add - SecurityConstants.ALLOWED_CAPABILITIES
            if disallowed:
                self.add_violation(
                    cve_id=K8SCVEIDs.DISALLOWED_CAPABILITIES,
                    severity="Medium",
                    resource=resource,
                    key_path=f"{path_prefix}.{ctype}[].securityContext.capabilities.add",
                    message=f"Capabilities {disallowed} are not allowed."
                )