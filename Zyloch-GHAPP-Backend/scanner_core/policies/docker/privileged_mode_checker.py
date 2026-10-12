from typing import Dict, List, Any
from scanner_core.policies.docker.base_checker import BaseDockerSecurityChecker
from scanner_core.models.violation import DockerSecurityViolation
from scanner_core.constants.security_constants import DockerSecurityConstants


class PrivilegedModeChecker(BaseDockerSecurityChecker):
    """Check for containers running in privileged mode"""
    
    def check(self, contexts: List[Dict[str, Any]]) -> List[DockerSecurityViolation]:
        """Check for privileged mode in Docker files"""
        self.reset_violations()
        
        for context in contexts:
            if context.get('file_type') == "docker-compose":
                self.check_docker_compose(context)
        
        return self.violations
    
    def check_docker_compose(self, context: Dict[str, Any]) -> None:
        """Check docker-compose for privileged mode"""
        parsed_data = context.get('parsed_data', {})
        
        if 'services' in parsed_data:
            for service_name, service_config in parsed_data['services'].items():
                if service_config.get('privileged') is True:
                    self.add_violation(
                        cve_id="DOCKER-SEC-003",
                        severity=DockerSecurityConstants.SEVERITY_HIGH,
                        resource={
                            'file_path': context.get('file_path'),
                            'file_type': 'docker-compose',
                            'line_number': getattr(service_config, '__line__', 0)
                        },
                        key_path=f"services.{service_name}.privileged",
                        message=f"Container '{service_name}' runs in privileged mode. Avoid using privileged mode unless absolutely necessary.",
                        service_name=service_name
                    )
    
    def reset_violations(self) -> None:
        """Reset violations list"""
        self.violations = []