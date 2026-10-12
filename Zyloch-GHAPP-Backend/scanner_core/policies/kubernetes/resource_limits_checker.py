from typing import Dict, List, Any
from scanner_core.policies.kubernetes.base_checker import BaseSecurityChecker
from scanner_core.models.violation import PolicyViolation
from scanner_core.constants.security_constants import SecurityConstants
from scanner_core.constants.k8s_cve_ids import K8SCVEIDs


class ResourceLimitsChecker(BaseSecurityChecker):
    """
    Validates resource requests and limits for containers.
    
    CVE IDs:
        - K8S-SEC-013: Missing resource requests/limits
    """
    
    SUPPORTED_KINDS = ["Pod"]
    
    def check(self, resources: List[Dict[str, Any]]) -> List[PolicyViolation]:
        """Check resource limits for all containers"""
        self.violations = []
        
        for resource in resources:
            if not self.should_check_resource(resource, self.SUPPORTED_KINDS):
                continue
            
            self._check_resource(resource)
        
        return self.violations
    
    def _check_resource(self, resource: Dict[str, Any]) -> None:
        """Check a single resource for resource limit violations"""
        pod_spec = self.helper.safe_get(resource, "spec", default={})
        
        for ctype, idx, container in self.helper.get_containers(pod_spec):
            # ephemeralContainers cannot have `resources` set at all - the
            # Kubernetes API rejects/ignores it on EphemeralContainer objects,
            # so flagging one as "missing resources" is not remediable and
            # not a real violation.
            if ctype == "ephemeralContainers":
                continue
            if not self._has_complete_resources(container):
                container_name = container.get("name", "unknown")
                
                self.add_violation(
                    cve_id=K8SCVEIDs.MISSING_RESOURCE_LIMITS,
                    severity=SecurityConstants.SEVERITY_MEDIUM,
                    resource=resource,
                    key_path=f"spec.{ctype}[{idx}].resources",
                    message=(
                        f"Container '{container_name}' is missing resource "
                        "requests and/or limits."
                    ),
                    container_name=container_name,
                    container_type=ctype,
                    container_index=idx
                )
    
    def _has_complete_resources(self, container: Dict[str, Any]) -> bool:
        """Check if container has both requests and limits"""
        resources = container.get("resources", {})
        return bool(resources.get("requests") and resources.get("limits"))

