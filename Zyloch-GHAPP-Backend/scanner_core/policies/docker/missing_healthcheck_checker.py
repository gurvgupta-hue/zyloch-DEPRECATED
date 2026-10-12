from typing import Dict, List, Any
from scanner_core.policies.docker.base_checker import BaseDockerSecurityChecker
from scanner_core.models.violation import DockerSecurityViolation
from scanner_core.helpers.docker_helper import DockerfileInstruction
from scanner_core.constants.security_constants import DockerSecurityConstants


class MissingHealthcheckChecker(BaseDockerSecurityChecker):
    """Check for missing HEALTHCHECK instructions"""
    
    def check(self, contexts: List[Dict[str, Any]]) -> List[DockerSecurityViolation]:
        """Check for missing healthchecks in Docker files"""
        self.reset_violations()
        
        for context in contexts:
            if context.get('file_type') == "Dockerfile":
                self.check_dockerfile(context.get('file_path'), context.get('instruction_objects', []))
            elif context.get('file_type') == "docker-compose":
                self.check_docker_compose(context)
        
        return self.violations
    
    def check_dockerfile(self, dockerfile_path: str, instructions: List[DockerfileInstruction]) -> None:
        """Check for missing HEALTHCHECK instruction in Dockerfile"""
        
        # Check if HEALTHCHECK instruction is present
        healthcheck_instructions = [inst for inst in instructions if inst.instruction.lower() == "healthcheck"]
        
        if not healthcheck_instructions:
            # Not tied to a specific instruction - anchor on the last line of
            # the file, since that's where a HEALTHCHECK would typically go.
            anchor = instructions[-1] if instructions else None
            self._add_healthcheck_violation(
                dockerfile_path,
                anchor,
                "HEALTHCHECK instruction missing. Consider adding health checks for better container monitoring."
            )
    
    def check_docker_compose(self, context: Dict[str, Any]) -> None:
        """Check docker-compose for missing healthcheck configuration"""
        parsed_data = context.get('parsed_data', {})
        
        if 'services' in parsed_data:
            for service_name, service_config in parsed_data['services'].items():
                # Check if healthcheck is configured
                if 'healthcheck' not in service_config:
                    self._add_healthcheck_violation(
                        context.get('file_path'),
                        getattr(service_config, '__line__', 0),
                        f"Service '{service_name}' missing healthcheck configuration. Consider adding healthcheck for better monitoring.",
                        service_name
                    )

    def _add_healthcheck_violation(self, resource_name: str, instruction,
                                   message: str, service_name: str = None) -> None:
        """Add a missing healthcheck violation.

        `instruction` is either a DockerfileInstruction (Dockerfile case)
        or a plain int line number (docker-compose service case).
        """

        cve_id = "DOCKER-SEC-011"

        if isinstance(instruction, DockerfileInstruction):
            line_number = instruction.line_number
        elif isinstance(instruction, int):
            line_number = instruction
        else:
            line_number = 0
        instruction_text = "Missing HEALTHCHECK"
        
        self.add_violation(
            cve_id=cve_id,
            severity=DockerSecurityConstants.SEVERITY_MEDIUM,
            resource={
                'file_path': resource_name,
                'file_type': 'Dockerfile' if not service_name else 'docker-compose',
                'line_number': line_number
            },
            key_path=instruction_text,
            message=message,
            service_name=service_name,
            checker="MissingHealthcheckChecker"
        )