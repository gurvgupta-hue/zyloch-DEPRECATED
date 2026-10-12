from typing import Dict, List, Any
from scanner_core.policies.kubernetes.base_checker import BaseSecurityChecker
from scanner_core.models.violation import PolicyViolation
from scanner_core.constants.security_constants import SecurityConstants
from scanner_core.constants.k8s_cve_ids import K8SCVEIDs


class ImagePullPolicyChecker(BaseSecurityChecker):
    """
    Validates imagePullPolicy for all containers.
    
    CVE IDs:
        - K8S-SEC-007: imagePullPolicy violations
    """
    
    REQUIRED_PULL_POLICY = "Always"
    SUPPORTED_KINDS = ["Deployment", "DaemonSet", "Pod"]
    
    def check(self, resources: List[Dict[str, Any]]) -> List[PolicyViolation]:
        """Check imagePullPolicy for all containers"""
        self.violations = []
        
        for resource in resources:
            if not self.should_check_resource(resource, self.SUPPORTED_KINDS):
                continue
            
            self._check_resource(resource)
        
        return self.violations
    
    def _check_resource(self, resource: Dict[str, Any]) -> None:
        """Check a single resource for pull policy violations"""
        kind = resource.get("kind")
        pod_spec = self.helper.get_pod_spec(resource)
        path_prefix = self.helper.get_path_prefix(kind)
        
        violating_containers = self._find_violating_containers(pod_spec)
        
        if violating_containers:
            cve_id = K8SCVEIDs.IMAGE_PULL_POLICY
            container_names = ", ".join(violating_containers)
            
            self.add_violation(
                cve_id=cve_id,
                severity=SecurityConstants.SEVERITY_MEDIUM,
                resource=resource,
                key_path=f"{path_prefix}.containers[].imagePullPolicy",
                message=(
                    f"Container(s) [{container_names}] do not have "
                    f"imagePullPolicy set to '{self.REQUIRED_PULL_POLICY}'."
                ),
                violating_containers=violating_containers
            )
    
    def _find_violating_containers(self, pod_spec: Dict[str, Any]) -> List[str]:
        """Find containers with incorrect pull policy"""
        violating = []
        
        for ctype, idx, container in self.helper.get_containers(pod_spec):
            pull_policy = container.get("imagePullPolicy", "")
            if pull_policy != self.REQUIRED_PULL_POLICY:
                container_name = container.get("name", f"container-{idx}")
                violating.append(container_name)
        
        return violating
