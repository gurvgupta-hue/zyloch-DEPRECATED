from typing import Dict, List, Any
from scanner_core.policies.docker.base_checker import BaseDockerSecurityChecker
from scanner_core.models.violation import DockerSecurityViolation
from scanner_core.constants.security_constants import DockerSecurityConstants


class VolumeMountsChecker(BaseDockerSecurityChecker):
    """Check for overly permissive volume mounts"""
    
    DANGEROUS_MOUNT_PATHS = {"/", "/etc", "/sys", "/proc", "/dev", "/root"}
    
    def check(self, contexts: List[Dict[str, Any]]) -> List[DockerSecurityViolation]:
        """Check for dangerous volume mounts in Docker files"""
        self.reset_violations()
        
        for context in contexts:
            if context.get('file_type') == "docker-compose":
                self.check_docker_compose(context)
        
        return self.violations
    
    def check_docker_compose(self, context: Dict[str, Any]) -> None:
        """Check docker-compose for overly permissive volume mounts"""
        parsed_data = context.get('parsed_data', {})
        
        if 'services' in parsed_data:
            for service_name, service_config in parsed_data['services'].items():
                volumes = service_config.get('volumes', [])
                if isinstance(volumes, list):
                    for volume in volumes:
                        if isinstance(volume, str):
                            # Parse volume mount format: "source:destination:mode".
                            # A colon-less entry ("/root") is a Docker-managed
                            # anonymous volume - no host path is involved at
                            # all, so it cannot leak a host system directory
                            # and must not be checked as a host bind mount.
                            if ':' not in volume:
                                continue
                            mount_path = volume.split(':')[1]
                            if mount_path in self.DANGEROUS_MOUNT_PATHS:
                                severity = DockerSecurityConstants.SEVERITY_CRITICAL if mount_path == "/" else DockerSecurityConstants.SEVERITY_HIGH
                                self.add_violation(
                                    cve_id="DOCKER-SEC-012",
                                    severity=severity,
                                    resource={
                                        'file_path': context.get('file_path'),
                                        'file_type': 'docker-compose',
                                        'line_number': getattr(service_config, '__line__', 0)
                                    },
                                    key_path=f"services.{service_name}.volumes",
                                    message=f"Container '{service_name}' has sensitive path mounted: {mount_path}. Avoid mounting critical system directories.",
                                    service_name=service_name,
                                    mount_path=mount_path
                                )
    
    def reset_violations(self) -> None:
        """Reset violations list"""
        self.violations = []