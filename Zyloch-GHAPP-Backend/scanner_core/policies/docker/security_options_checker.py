from typing import Dict, List, Any
from scanner_core.policies.docker.base_checker import BaseDockerSecurityChecker
from scanner_core.models.violation import DockerSecurityViolation
from scanner_core.constants.security_constants import DockerSecurityConstants


class SecurityOptionsChecker(BaseDockerSecurityChecker):
    """Check for missing security options"""
    
    def check(self, contexts: List[Dict[str, Any]]) -> List[DockerSecurityViolation]:
        """Check for security options in Docker files"""
        self.reset_violations()
        
        for context in contexts:
            if context.get('file_type') == "docker-compose":
                self.check_docker_compose(context)
        
        return self.violations
    
    def check_docker_compose(self, context: Dict[str, Any]) -> None:
        """Check docker-compose for security options"""
        parsed_data = context.get('parsed_data', {})
        
        if 'services' in parsed_data:
            for service_name, service_config in parsed_data['services'].items():
                security_opt = service_config.get('security_opt', [])
                
                if not security_opt:
                    self.add_violation(
                        cve_id="DOCKER-SEC-017",
                        severity=DockerSecurityConstants.SEVERITY_MEDIUM,
                        resource={
                            'file_path': context.get('file_path'),
                            'file_type': 'docker-compose',
                            'line_number': getattr(service_config, '__line__', 0)
                        },
                        key_path=f"services.{service_name}.security_opt",
                        message=f"Container '{service_name}' has no security options configured. Consider adding AppArmor, SELinux, or seccomp profiles.",
                        service_name=service_name
                    )
    
    def reset_violations(self) -> None:
        """Reset violations list"""
        self.violations = []