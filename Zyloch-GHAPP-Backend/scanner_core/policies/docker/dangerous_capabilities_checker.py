from typing import Dict, List, Any
from scanner_core.policies.docker.base_checker import BaseDockerSecurityChecker
from scanner_core.models.violation import DockerSecurityViolation
from scanner_core.constants.security_constants import DockerSecurityConstants


class DangerousCapabilitiesChecker(BaseDockerSecurityChecker):
    """Check for dangerous capabilities added to containers"""
    
    DANGEROUS_CAPABILITIES = DockerSecurityConstants.DANGEROUS_CAPABILITIES
    
    def check(self, contexts: List[Dict[str, Any]]) -> List[DockerSecurityViolation]:
        """Check for dangerous capabilities in Docker files"""
        self.reset_violations()
        
        for context in contexts:
            if context.get('file_type') == "docker-compose":
                self.check_docker_compose(context)
        
        return self.violations
    
    def check_docker_compose(self, context: Dict[str, Any]) -> None:
        """Check docker-compose for dangerous capabilities"""
        parsed_data = context.get('parsed_data', {})
        
        if 'services' in parsed_data:
            for service_name, service_config in parsed_data['services'].items():
                cap_add = service_config.get('cap_add', [])
                if isinstance(cap_add, list):
                    for cap in cap_add:
                        if cap in self.DANGEROUS_CAPABILITIES:
                            self.add_violation(
                                cve_id="DOCKER-SEC-004",
                                severity=DockerSecurityConstants.SEVERITY_CRITICAL,
                                resource={
                                    'file_path': context.get('file_path'),
                                    'file_type': 'docker-compose',
                                    'line_number': getattr(service_config, '__line__', 0)
                                },
                                key_path=f"services.{service_name}.cap_add",
                                message=f"Dangerous capability '{cap}' added to container '{service_name}'.",
                                service_name=service_name,
                                capability=cap
                            )
    
    def reset_violations(self) -> None:
        """Reset violations list"""
        self.violations = []