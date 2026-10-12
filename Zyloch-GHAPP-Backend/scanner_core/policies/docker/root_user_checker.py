from typing import List, Dict, Any
from scanner_core.policies.docker.base_checker import BaseDockerSecurityChecker
from scanner_core.models.violation import DockerSecurityViolation
from scanner_core.helpers.docker_helper import DockerfileInstruction
from scanner_core.constants.security_constants import DockerSecurityConstants


class RootUserChecker(BaseDockerSecurityChecker):
    """Check for containers running as root user"""
    
    def check(self, contexts: List[Dict[str, Any]]) -> List[DockerSecurityViolation]:
        """Check for root user usage in Docker files"""
        self.reset_violations()
        
        for context in contexts:
            if context.get('file_type') == "Dockerfile":
                self.check_dockerfile(context.get('file_path'), context.get('instruction_objects', []))
            elif context.get('file_type') == "docker-compose":
                self.check_docker_compose(context)
        
        return self.violations
    
    def check_dockerfile(self, dockerfile_path: str, instructions: List[DockerfileInstruction]) -> None:
        """Check Dockerfile for root user usage"""

        # Only the final build stage actually ships in the resulting image;
        # a builder stage running as root (or setting USER root to install
        # packages) is discarded and never runs in production, so it must
        # not be evaluated. Split instructions on FROM boundaries and only
        # consider the last stage.
        last_stage_instructions = instructions
        from_indices = [i for i, inst in enumerate(instructions) if inst.instruction.lower() == "from"]
        if len(from_indices) > 1:
            last_stage_instructions = instructions[from_indices[-1]:]

        # Check if USER instruction is present
        user_instructions = [inst for inst in last_stage_instructions if inst.instruction.lower() == "user"]
        
        if not user_instructions:
            # No USER instruction to anchor on - point at the FROM instruction
            # of the final stage (the stage that actually ships), not the
            # last instruction of the whole file, which could be an unrelated
            # instruction dozens of lines later in a multi-stage build and
            # gives a misleading line number.
            anchor = last_stage_instructions[0] if last_stage_instructions else None
            self._add_root_user_violation(
                dockerfile_path,
                anchor,
                "No USER instruction found in the final build stage, so the container runs as root "
                "by default (unless the base image itself already switches to a non-root user). "
                "Add a USER instruction with a non-root user.",
                key_path_override="No USER instruction"
            )
        else:
            # Only the last USER instruction in the final stage determines the
            # effective runtime user - an earlier `USER root` (e.g. to install
            # packages) that is later overridden by `USER appuser` is not a
            # violation.
            instruction = user_instructions[-1]
            user_value = instruction.args.strip()
            if user_value.lower() in ['root', '0', 'uid=0']:
                self._add_root_user_violation(
                    dockerfile_path,
                    instruction,
                    f"Explicitly set to run as root user: {user_value}. Consider using a non-root user."
                )
    
    def check_docker_compose(self, context: Dict[str, Any]) -> None:
        """Check docker-compose for root user configuration"""
        parsed_data = context.get('parsed_data', {})
        
        if 'services' in parsed_data:
            for service_name, service_config in parsed_data['services'].items():
                if 'user' in service_config:
                    user_value = str(service_config['user'])
                    if user_value.lower() in ['root', '0', 'uid=0']:
                        self._add_root_user_violation(
                            context.get('file_path'),
                            getattr(service_config, '__line__', 0),
                            f"Service '{service_name}' explicitly set to run as root user: {user_value}.",
                            service_name
                        )

    def _add_root_user_violation(self, resource_name: str, instruction,
                                  message: str, service_name: str = None,
                                  key_path_override: str = None) -> None:
        """Add a root user violation.

        `instruction` is a DockerfileInstruction (Dockerfile case), a plain
        int line number (docker-compose service case), or None.
        """

        cve_id = "DOCKER-SEC-002"

        if isinstance(instruction, DockerfileInstruction):
            line_number = instruction.line_number
            instruction_text = str(instruction)
        elif isinstance(instruction, int):
            line_number = instruction
            instruction_text = "No USER instruction" if not service_name else "user"
        else:
            line_number = 0
            instruction_text = "No USER instruction"

        if key_path_override:
            instruction_text = key_path_override
        
        self.add_violation(
            cve_id=cve_id,
            severity=DockerSecurityConstants.SEVERITY_HIGH,
            resource={
                'file_path': resource_name,
                'file_type': 'Dockerfile' if not service_name else 'docker-compose',
                'line_number': line_number
            },
            key_path=instruction_text,
            message=message,
            service_name=service_name,
            checker="RootUserChecker"
        )