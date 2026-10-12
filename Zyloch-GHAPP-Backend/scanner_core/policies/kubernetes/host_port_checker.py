
from typing import Dict, List, Any
from scanner_core.policies.kubernetes.base_checker import BaseSecurityChecker
from scanner_core.models.violation import PolicyViolation
from scanner_core.constants.security_constants import SecurityConstants
from scanner_core.constants.k8s_cve_ids import K8SCVEIDs
class HostPortChecker(BaseSecurityChecker):
    """ Check for hostPort usage in containers
    
    Validates that no containers are using hostPort.
    
    CVE IDs:
        - K8S-SEC-005: hostPort usage detected in Pod/Deployment/DaemonSet
    """
    
    SUPPORTED_KINDS = ["Pod", "Deployment", "DaemonSet"]
    
    def check(self, resources: List[Dict[str, Any]]) -> List[PolicyViolation]:
        """Check hostPort setting for all resources"""
        self.violations = []
        
        for resource in resources:
            if not self.should_check_resource(resource, self.SUPPORTED_KINDS):
                continue
            
            self._check_resource(resource)
        
        return self.violations
    
    def _check_resource(self, resource: Dict[str, Any]) -> None:
        """Check a single resource for hostPort violations"""
        kind = resource.get("kind", "")
        pod_spec = self.helper.get_pod_spec(resource)
        path_prefix = self.helper.get_path_prefix(kind)
        
        # Use consistent CVE ID
        cve_id = K8SCVEIDs.HOST_PORT_USAGE
        
        for ctype, idx, container in self.helper.get_containers(pod_spec):
            ports = container.get("ports", [])
            for pidx, port in enumerate(ports):
                host_port = port.get("hostPort")
                
                if host_port is not None:
                    container_name = container.get("name", f"container-{idx}")
                    self.add_violation(
                        cve_id=cve_id,
                        severity=SecurityConstants.SEVERITY_HIGH,
                        resource=resource,
                        key_path=f"{path_prefix}.{ctype}[{idx}].ports[{pidx}].hostPort",
                        message=(
                            f"hostPort is forbidden in resource kind {kind}. "
                            f"Container '{container_name}' in {ctype}[{idx}] must not use hostPort."
                        )
                    )