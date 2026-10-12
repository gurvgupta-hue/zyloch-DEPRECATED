from typing import Dict, List, Any
from scanner_core.policies.docker.base_checker import BaseDockerSecurityChecker
from scanner_core.models.violation import DockerSecurityViolation
from scanner_core.constants.security_constants import DockerSecurityConstants


class ResourceLimitsChecker(BaseDockerSecurityChecker):
    """Check for missing resource limits"""
    
    def check(self, contexts: List[Dict[str, Any]]) -> List[DockerSecurityViolation]:
        """Check for resource limits in Docker files"""
        self.reset_violations()
        
        for context in contexts:
            if context.get('file_type') == "docker-compose":
                self.check_docker_compose(context)
        
        return self.violations
    
    def check_docker_compose(self, context: Dict[str, Any]) -> None:
        """Check docker-compose for resource limits"""
        parsed_data = context.get('parsed_data', {})
        
        if 'services' in parsed_data:
            for service_name, service_config in parsed_data['services'].items():
                # Check for deploy section with resources limits
                deploy = service_config.get('deploy', {})
                resources = deploy.get('resources', {})
                limits = resources.get('limits', {})
                
                if not limits or ('cpus' not in limits and 'memory' not in limits):
                    self.add_violation(
                        cve_id="DOCKER-SEC-014",
                        severity=DockerSecurityConstants.SEVERITY_MEDIUM,
                        resource={
                            'file_path': context.get('file_path'),
                            'file_type': 'docker-compose',
                            'line_number': getattr(deploy, '__line__', getattr(service_config, '__line__', 0))
                        },
                        key_path=f"services.{service_name}.deploy.resources.limits",
                        message=f"Container '{service_name}' has no resource limits defined. Define memory and CPU limits.",
                        service_name=service_name
                    )
    
    def reset_violations(self) -> None:
        """Reset violations list"""
        self.violations = []