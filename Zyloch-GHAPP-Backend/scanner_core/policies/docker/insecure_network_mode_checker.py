from typing import Dict, List, Any
from scanner_core.policies.docker.base_checker import BaseDockerSecurityChecker
from scanner_core.models.violation import DockerSecurityViolation
from scanner_core.constants.security_constants import DockerSecurityConstants


class InsecureNetworkModeChecker(BaseDockerSecurityChecker):
    """Check for insecure network modes"""
    
    INSECURE_NETWORK_MODES = {"host", "container"}
    
    def check(self, contexts: List[Dict[str, Any]]) -> List[DockerSecurityViolation]:
        """Check for insecure network modes in Docker files"""
        self.reset_violations()
        
        for context in contexts:
            if context.get('file_type') == "docker-compose":
                self.check_docker_compose(context)
        
        return self.violations
    
    def check_docker_compose(self, context: Dict[str, Any]) -> None:
        """Check docker-compose for insecure network modes"""
        parsed_data = context.get('parsed_data', {})
        
        if 'services' in parsed_data:
            for service_name, service_config in parsed_data['services'].items():
                network_mode = service_config.get('network_mode', '').lower()
                if network_mode in self.INSECURE_NETWORK_MODES:
                    self.add_violation(
                        cve_id="DOCKER-SEC-010",
                        severity=DockerSecurityConstants.SEVERITY_HIGH,
                        resource={
                            'file_path': context.get('file_path'),
                            'file_type': 'docker-compose',
                            'line_number': getattr(service_config, '__line__', 0)
                        },
                        key_path=f"services.{service_name}.network_mode",
                        message=f"Container '{service_name}' uses insecure network mode: {network_mode}. Consider using bridge or custom networks.",
                        service_name=service_name,
                        network_mode=network_mode
                    )
    
    def reset_violations(self) -> None:
        """Reset violations list"""
        self.violations = []