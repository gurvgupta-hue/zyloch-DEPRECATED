from typing import Dict, List, Any
from scanner_core.policies.docker.base_checker import BaseDockerSecurityChecker
from scanner_core.models.violation import DockerSecurityViolation
from scanner_core.constants.security_constants import DockerSecurityConstants


class RestartPolicyChecker(BaseDockerSecurityChecker):
    """Check for insecure restart policies"""
    
    def check(self, contexts: List[Dict[str, Any]]) -> List[DockerSecurityViolation]:
        """Check for restart policies in Docker files"""
        self.reset_violations()
        
        for context in contexts:
            if context.get('file_type') == "docker-compose":
                self.check_docker_compose(context)
        
        return self.violations
    
    def check_docker_compose(self, context: Dict[str, Any]) -> None:
        """Check docker-compose for insecure restart policies"""
        parsed_data = context.get('parsed_data', {})
        
        if 'services' in parsed_data:
            for service_name, service_config in parsed_data['services'].items():
                restart_policy = service_config.get('restart_policy', {})
                
                if isinstance(restart_policy, dict):
                    policy_name = restart_policy.get('name', '').lower()
                    if policy_name == 'always' and 'max_retry_count' not in restart_policy:
                        self.add_violation(
                            cve_id="DOCKER-SEC-015",
                            severity=DockerSecurityConstants.SEVERITY_MEDIUM,
                            resource={
                                'file_path': context.get('file_path'),
                                'file_type': 'docker-compose',
                                'line_number': getattr(restart_policy, '__line__', getattr(service_config, '__line__', 0))
                            },
                            key_path=f"services.{service_name}.restart_policy",
                            message=f"Container '{service_name}' has 'always' restart policy without retry limits.",
                            service_name=service_name,
                            policy=policy_name
                        )
    
    def reset_violations(self) -> None:
        """Reset violations list"""
        self.violations = []