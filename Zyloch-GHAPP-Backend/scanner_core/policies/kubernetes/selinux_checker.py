from typing import Dict, List, Any
from scanner_core.policies.kubernetes.base_checker import BaseSecurityChecker
from scanner_core.models.violation import PolicyViolation
from scanner_core.constants.security_constants import SecurityConstants
from scanner_core.constants.k8s_cve_ids import K8SCVEIDs

class selinuxChecker(BaseSecurityChecker):
    """K8S-SEC-015: Check for disallowed SELinux options"""
    
    SUPPORTED_KINDS = ["Deployment", "DaemonSet", "Pod"]
    def check(self, resources: List[Dict[str, Any]]) -> List[PolicyViolation]:
        """Check SELinux options for all containers"""
        self.violations = []
        
        for resource in resources:
            if not self.should_check_resource(resource, self.SUPPORTED_KINDS):
                continue
            
            self.check_selinux_options(resource)
        
        return self.violations
    
    def check_selinux_options(self, resource: Dict[str, Any]) -> None:
        """K8S-SEC-015-020: Check SELinux options"""
        kind = resource.get("kind", "")
        if kind not in ["Deployment", "DaemonSet", "Pod"]:
            return
        
        pod_spec = self.helper.get_pod_spec(resource)
        path_prefix = self.helper.get_path_prefix(kind)
        
        # Check pod-level SELinux options
        sec_ctx = self.helper.safe_get(pod_spec, "securityContext", default={})
        selinux_opts = self.helper.safe_get(sec_ctx, "seLinuxOptions", default={})
        
        # Check user
        if selinux_opts.get("user"):
            cve_id = K8SCVEIDs.SELINUX_USER_POD
            self.add_violation(
                cve_id=cve_id,
                severity="Medium",
                resource=resource,
                key_path=f"{path_prefix}.securityContext.seLinuxOptions.user",
                message="Setting the SELinux user is forbidden. The field must be unset."
            )
        
        # Check role
        if selinux_opts.get("role"):
            cve_id = K8SCVEIDs.SELINUX_ROLE_POD
            self.add_violation(
                cve_id=cve_id,
                severity="Medium",
                resource=resource,
                key_path=f"{path_prefix}.securityContext.seLinuxOptions.role",
                message="Setting the SELinux role is forbidden. The field must be unset."
            )
        
        # Check type
        se_type = selinux_opts.get("type", "")
        if se_type and se_type not in SecurityConstants.ALLOWED_SELINUX_TYPES:
            cve_id = K8SCVEIDs.SELINUX_TYPE_POD
            self.add_violation(
                cve_id=cve_id,
                severity="Medium",
                resource=resource,
                key_path=f"{path_prefix}.securityContext.seLinuxOptions.type",
                message=f"SELinux type '{se_type}' is restricted. Must be container_t, container_init_t, or container_kvm_t."
            )
        
        # Check container-level SELinux options
        for ctype, idx, container in self.helper.get_containers(pod_spec):
            sec_ctx = self.helper.safe_get(container, "securityContext", default={})
            selinux_opts = self.helper.safe_get(sec_ctx, "seLinuxOptions", default={})
            container_name = container.get("name", f"container-{idx}")
            
            # Check user
            if selinux_opts.get("user"):
                cve_id = K8SCVEIDs.SELINUX_USER_CONTAINER
                self.add_violation(
                    cve_id=cve_id,
                    severity="Medium",
                    resource=resource,
                    key_path=f"{path_prefix}.{ctype}[{idx}].securityContext.seLinuxOptions.user",
                    message=f"Container '{container_name}': Setting the SELinux user is forbidden."
                )
            
            # Check role
            if selinux_opts.get("role"):
                cve_id = K8SCVEIDs.SELINUX_ROLE_CONTAINER
                self.add_violation(
                    cve_id=cve_id,
                    severity="Medium",
                    resource=resource,
                    key_path=f"{path_prefix}.{ctype}[{idx}].securityContext.seLinuxOptions.role",
                    message=f"Container '{container_name}': Setting the SELinux role is forbidden."
                )
            
            # Check type
            se_type = selinux_opts.get("type", "")
            if se_type and se_type not in SecurityConstants.ALLOWED_SELINUX_TYPES:
                cve_id = K8SCVEIDs.SELINUX_TYPE_CONTAINER
                self.add_violation(
                    cve_id=cve_id,
                    severity="Medium",
                    resource=resource,
                    key_path=f"{path_prefix}.{ctype}[{idx}].securityContext.seLinuxOptions.type",
                    message=f"Container '{container_name}': SELinux type '{se_type}' is restricted."
                )
        