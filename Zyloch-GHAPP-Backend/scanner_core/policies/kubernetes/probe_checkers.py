from typing import Dict, List, Any
from scanner_core.policies.kubernetes.base_checker import BaseSecurityChecker
from scanner_core.models.violation import PolicyViolation
from scanner_core.constants.security_constants import SecurityConstants
from scanner_core.constants.k8s_cve_ids import K8SCVEIDs


class ProbeChecker(BaseSecurityChecker):
    """
    Validates liveness and readiness probes for containers.
    
    CVE IDs:
        - K8S-SEC-010: Missing readinessProbe
        - K8S-SEC-011: Missing livenessProbe
    """
    
    SUPPORTED_KINDS = ["Deployment", "DaemonSet", "Pod"]
    
    def check(self, resources: List[Dict[str, Any]]) -> List[PolicyViolation]:
        """Check probes for all containers"""
        self.violations = []
        
        for resource in resources:
            if not self.should_check_resource(resource, self.SUPPORTED_KINDS):
                continue
            
            self._check_resource(resource)
        
        return self.violations
    
    def _check_resource(self, resource: Dict[str, Any]) -> None:
        """Check a single resource for probe violations"""
        kind = resource.get("kind")
        pod_spec = self.helper.get_pod_spec(resource)
        path_prefix = self.helper.get_path_prefix(kind)
        
        for ctype, idx, container in self.helper.get_containers(pod_spec):
            # readinessProbe/livenessProbe are invalid on initContainers and
            # ephemeralContainers - the Kubernetes API rejects them there, so
            # flagging either as "missing a probe" is unremediable and not a
            # real violation.
            if ctype in ("initContainers", "ephemeralContainers"):
                continue

            container_name = container.get("name", f"container-{idx}")

            # Check readiness probe
            if not container.get("readinessProbe"):
                cve_id = K8SCVEIDs.MISSING_READINESS_PROBE
                self.add_violation(
                    cve_id=cve_id,
                    severity=SecurityConstants.SEVERITY_MEDIUM,
                    resource=resource,
                    key_path=f"{path_prefix}.{ctype}[{idx}].readinessProbe",
                    message=f"Container '{container_name}' missing readinessProbe.",
                    container_name=container_name,
                    probe_type="readiness"
                )
            
            # Check liveness probe
            if not container.get("livenessProbe"):
                cve_id = K8SCVEIDs.MISSING_LIVENESS_PROBE
                self.add_violation(
                    cve_id=cve_id,
                    severity=SecurityConstants.SEVERITY_MEDIUM,
                    resource=resource,
                    key_path=f"{path_prefix}.{ctype}[{idx}].livenessProbe",
                    message=f"Container '{container_name}' missing livenessProbe.",
                    container_name=container_name,
                    probe_type="liveness"
                )

