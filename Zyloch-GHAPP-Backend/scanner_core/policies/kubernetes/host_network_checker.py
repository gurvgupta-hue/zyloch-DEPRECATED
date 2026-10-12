from typing import Dict, List, Any
from scanner_core.policies.kubernetes.base_checker import BaseSecurityChecker
from scanner_core.models.violation import PolicyViolation
from scanner_core.constants.security_constants import SecurityConstants
from scanner_core.constants.k8s_cve_ids import K8SCVEIDs

class HostNetworkChecker(BaseSecurityChecker):
    """
    # Deny use of hostNetwork in Deployment, DaemonSet, or Pod
    # Deny use of hostIPC in Deployment, DaemonSet, or Pod
    # Deny use of hostPID in Deployment, DaemonSet, or Pod
    CVE IDs:
        - K8S-SEC-011: hostNetwork enabled
        - K8S-SEC-012: hostNetwork enabled
        - K8S-SEC-013: hostNetwork enabled
    """
    
    SUPPORTED_KINDS = ["Pod","Deployment", "DaemonSet"]
    
    def check(self, resources: List[Dict[str, Any]]) -> List[PolicyViolation]:
        """Check hostNetwork setting for all resources"""
        self.violations = []
        
        for resource in resources:
            if not self.should_check_resource(resource, self.SUPPORTED_KINDS):
                continue
            
            self._check_resource(resource)
        
        return self.violations
    
    def _check_resource(self, resource: Dict[str, Any]) -> None:
        """Check a single resource for hostNetwork, hostIPC, and hostPID violations"""
        kind = resource.get("kind", "")
        
        # Get the pod spec based on resource kind
        if kind == "Pod":
            pod_spec = self.helper.safe_get(resource, "spec", default={})
            path_prefix = "spec"
        elif kind in ["Deployment", "DaemonSet"]:
            pod_spec = self.helper.safe_get(resource, "spec.template.spec", default={})
            path_prefix = "spec.template.spec"
        else:
            return
        
        # Check hostNetwork
        host_network = pod_spec.get("hostNetwork", False)
        if host_network:
            self.add_violation(
                cve_id=K8SCVEIDs.HOST_NETWORK_USAGE,
                severity=SecurityConstants.SEVERITY_HIGH,
                resource=resource,
                key_path=f"{path_prefix}.hostNetwork",
                message="hostNetwork is enabled for the Pod.",
            )
        
        # Check hostIPC
        host_ipc = pod_spec.get("hostIPC", False)
        if host_ipc:
            self.add_violation(
                cve_id=K8SCVEIDs.HOST_IPC_USAGE,
                severity=SecurityConstants.SEVERITY_HIGH,
                resource=resource,
                key_path=f"{path_prefix}.hostIPC",
                message="hostIPC is enabled for the Pod.",
            )
        
        # Check hostPID
        host_pid = pod_spec.get("hostPID", False)
        if host_pid:
            self.add_violation(
                cve_id=K8SCVEIDs.HOST_PID_USAGE,
                severity=SecurityConstants.SEVERITY_HIGH,
                resource=resource,
                key_path=f"{path_prefix}.hostPID",
                message="hostPID is enabled for the Pod.",
            )
