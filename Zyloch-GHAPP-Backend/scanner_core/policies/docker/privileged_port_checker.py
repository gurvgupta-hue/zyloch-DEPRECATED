from typing import List, Dict, Any
from scanner_core.policies.docker.base_checker import BaseDockerSecurityChecker
from scanner_core.models.violation import DockerSecurityViolation
from scanner_core.helpers.docker_helper import DockerfileInstruction
from scanner_core.constants.security_constants import DockerSecurityConstants


class PrivilegedPortChecker(BaseDockerSecurityChecker):
    """Check for privileged port exposure (ports < 1024)"""
    
    def check(self, contexts: List[Dict[str, Any]]) -> List[DockerSecurityViolation]:
        """Check for privileged port exposure in Docker files"""
        self.reset_violations()
        
        for context in contexts:
            # Note: Dockerfile EXPOSE is intentionally not checked here -
            # EXPOSE is pure documentation metadata that does not bind to any
            # host port or network interface, so it cannot itself expose a
            # privileged port. Only an actual host-port publish (docker-compose
            # `ports: "hostport:containerport"`, or `docker run -p`) does that.
            if context.get('file_type') == "docker-compose":
                self.check_docker_compose(context)

        return self.violations

    def check_docker_compose(self, context: Dict[str, Any]) -> None:
        """Check docker-compose for privileged port exposure"""
        parsed_data = context.get('parsed_data', {})
        
        if 'services' in parsed_data:
            for service_name, service_config in parsed_data['services'].items():
                # Check ports section
                if 'ports' in service_config:
                    ports = service_config['ports']
                    self._check_compose_ports(context.get('file_path'), ports, service_name)
    
    def _check_compose_ports(self, file_path: str, ports: List, service_name: str) -> None:
        """Check docker-compose ports for privileged port exposure"""

        for port_mapping in ports:
            port_str = str(port_mapping)

            # Handle different port mapping formats:
            # "80:8080" (host:container), "127.0.0.1:80:8080" (ip:host:container).
            # A bare value with no colon ("80") is the *container* port only -
            # Docker publishes it to a random, non-privileged ephemeral host
            # port, so it is not a host-exposure risk and must be skipped.
            if ':' not in port_str:
                continue

            host_port = port_str.split(':')[0]
            # Handle IP:port format
            if '.' in host_port:
                host_port = port_str.split(':')[-2]

            try:
                port_num = int(host_port)
                if port_num < 1024:
                    self._add_privileged_port_violation(
                        file_path,
                        None,
                        port_num,
                        f"Service '{service_name}' exposes privileged port {port_num}. Consider using ports >= 1024.",
                        service_name
                    )
            except ValueError:
                # Skip non-numeric port specifications
                continue
    
    def _add_privileged_port_violation(self, resource_name: str, instruction: DockerfileInstruction, 
                                       port: int, message: str, service_name: str = None) -> None:
        """Add a privileged port violation"""
                
        line_number = instruction.line_number if instruction else 0
        instruction_text = str(instruction) if instruction else f"ports: {port}"
        
        # Create context dict for add_violation
        self.add_violation(
            cve_id="DOCKER-SEC-023",
            severity=DockerSecurityConstants.SEVERITY_MEDIUM,
            resource={
                'file_path': resource_name,
                'file_type': 'Dockerfile' if not service_name else 'docker-compose',
                'line_number': line_number
            },
            key_path=instruction_text,
            message=message,
            port=port,
            service_name=service_name,
            checker="PrivilegedPortChecker"
        )