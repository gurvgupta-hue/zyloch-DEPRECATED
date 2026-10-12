from typing import Dict, List, Any
from scanner_core.policies.kubernetes.base_checker import BaseSecurityChecker
from scanner_core.models.violation import PolicyViolation
from scanner_core.constants.security_constants import SecurityConstants
from scanner_core.constants.k8s_cve_ids import K8SCVEIDs

class SecCompProfileChecker(BaseSecurityChecker):
    """Check for disallowed seccomp profiles"""
    """
    CVE IDs:    
        - K8S-SEC-014: Disallowed seccomp profiles in containers
    """
    
    SUPPORTED_KINDS = ["Deployment", "DaemonSet", "Pod"]
    
    def check(self, resources: List[Dict[str, Any]]) -> List[PolicyViolation]:
        """Check seccomp profiles for all containers"""
        self.violations = []
        
        for resource in resources:
            if not self.should_check_resource(resource, self.SUPPORTED_KINDS):
                continue
            
            self.check_seccomp_profiles(resource)
        
        return self.violations
    
    def check_seccomp_profiles(self, resource: Dict[str, Any]) -> None:
        """Check for disallowed seccomp profiles"""
        
        kind = resource.get("kind", "")
        if kind not in ["Deployment", "DaemonSet", "Pod"]:
            return
        
        pod_spec = self.helper.get_pod_spec(resource)
        path_prefix = self.helper.get_path_prefix(kind)
        
        # Pod-level securityContext.seccompProfile applies to every container
        # that doesn't set its own - only fall through to "disallowed" if
        # neither the container nor the pod specifies a valid profile.
        pod_sec_ctx = self.helper.safe_get(pod_spec, "securityContext", default={})
        pod_seccomp_profile = self.helper.safe_get(pod_sec_ctx, "seccompProfile", default={})

        for ctype, idx, container in self.helper.get_containers(pod_spec):
            sec_ctx = self.helper.safe_get(container, "securityContext", default={})
            seccomp_profile = self.helper.safe_get(sec_ctx, "seccompProfile", default=None)
            if not seccomp_profile:
                seccomp_profile = pod_seccomp_profile
            profile_type = seccomp_profile.get("type", "")
            profile_name = seccomp_profile.get("localhostProfile", "")
            
            # Allowed types: "RuntimeDefault" or "Localhost" with a valid profile name
            if profile_type == "RuntimeDefault":
                continue
            elif profile_type == "Localhost" and profile_name:
                continue
            else:
                self.add_violation(
                    cve_id=K8SCVEIDs.DISALLOWED_SECCOMP,
                    severity="Medium",
                    resource=resource,
                    key_path=f"{path_prefix}.{ctype}[].securityContext.seccompProfile",
                    message=(
                        f"Container '{container.get('name', f'container-{idx}')}' in resource kind {kind} "
                        f"has a disallowed seccomp profile configuration. "
                        f"The 'seccompProfile.type' must be either 'RuntimeDefault' or 'Localhost' "
                        f"with a valid 'localhostProfile' name."
                    )
                )