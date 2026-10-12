from typing import Dict, List, Any
from scanner_core.policies.kubernetes.base_checker import BaseSecurityChecker
from scanner_core.models.violation import PolicyViolation
from scanner_core.constants.security_constants import SecurityConstants
from scanner_core.constants.k8s_cve_ids import K8SCVEIDs

class SysCtlsChecker(BaseSecurityChecker):
    """K8S-SEC-021: Check for disallowed sysctls in Pod security context"""
    
    SUPPORTED_KINDS = ["Deployment", "DaemonSet", "Pod"]
    
    def check(self, resources: List[Dict[str, Any]]) -> List[PolicyViolation]:
        """Check sysctls for all Pods"""
        self.violations = []
        
        for resource in resources:
            if not self.should_check_resource(resource, self.SUPPORTED_KINDS):
                continue
            
            self.check_resource(resource)
        
        return self.violations
    
    def check_resource(self, resource: Dict[str, Any]) -> None:
        """K8S-SEC-021: Check for disallowed sysctls"""
        
        kind = resource.get("kind", "")
        if kind not in ["Deployment", "DaemonSet", "Pod"]:
            return
        
        # Get pod spec based on resource kind
        pod_spec = self.helper.get_pod_spec(resource)
        
        # Get security context from pod spec
        sec_ctx = self.helper.safe_get(pod_spec, "securityContext", default={})
        sysctls_array = self.helper.safe_get(sec_ctx, "sysctls", default=[])
        
        if not sysctls_array:
            return
        
        # Extract sysctl names
        sysctls = {sysctl.get("name") for sysctl in sysctls_array if sysctl.get("name")}
        
        # Define allowed sysctls
        allowed = {
            "kernel.shm_rmid_forced",
            "net.ipv4.ip_local_port_range",
            "net.ipv4.ip_unprivileged_port_start",
            "net.ipv4.tcp_syncookies",
            "net.ipv4.ping_group_range",
        }
        
        # Calculate disallowed sysctls
        disallowed = sysctls - allowed
        
        if disallowed:
            # Determine key path based on kind
            if kind == "Pod":
                key_path = "spec.securityContext.sysctls"
            else:  # Deployment or DaemonSet
                key_path = "spec.template.spec.securityContext.sysctls"
            
            resource_name = resource.get("metadata", {}).get("name", "unknown")
            
            self.add_violation(
                cve_id=K8SCVEIDs.DISALLOWED_SYSCTLS,
                severity="Medium",
                resource=resource,
                key_path=key_path,
                message=(
                    f"Setting additional sysctls above the allowed type is disallowed in resource "
                    f"'{resource_name}' (kind: {kind}). Please unset the sysctls {sorted(disallowed)}."
                )
            )