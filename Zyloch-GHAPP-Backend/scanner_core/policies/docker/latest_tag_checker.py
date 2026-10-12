import re
from typing import Dict, List, Any
from scanner_core.policies.docker.base_checker import BaseDockerSecurityChecker
from scanner_core.models.violation import DockerSecurityViolation
from scanner_core.helpers.docker_helper import DockerfileInstruction
from scanner_core.constants.security_constants import DockerSecurityConstants


class LatestTagChecker(BaseDockerSecurityChecker):
    """Check for latest or untagged Docker images"""
    
    def check(self, contexts: List[Dict[str, Any]]) -> List[DockerSecurityViolation]:
        """Check for latest tags in Docker files"""
        self.reset_violations()
        
        for context in contexts:
            if context.get('file_type') == "Dockerfile":
                self.check_dockerfile(context.get('file_path'), context.get('instruction_objects', []))
            elif context.get('file_type') == "docker-compose":
                self.check_docker_compose(context)
        
        return self.violations
    
    def check_dockerfile(self, dockerfile_path: str, instructions: List[DockerfileInstruction]) -> List[DockerSecurityViolation]:
        """Check for latest docker image used"""

        # Track ARG default values seen so far, so a `FROM ${BASE_IMAGE}` that
        # resolves to a fully pinned image via a preceding
        # `ARG BASE_IMAGE=python:3.11-slim` is not misread as untagged.
        arg_defaults: Dict[str, str] = {}
        # Stage aliases from `FROM ... AS <alias>` - a later `FROM <alias>`
        # references a previous build stage, not a pulled registry image, and
        # has no tag to speak of.
        stage_aliases: set = set()

        for instruction in instructions:
            if instruction.instruction.lower() == "arg" and instruction.args:
                arg_text = instruction.args.strip()
                if '=' in arg_text:
                    name, _, default = arg_text.partition('=')
                    arg_defaults[name.strip()] = default.strip().strip('"\'')
            elif instruction.instruction.lower() == "from":
                from_args = instruction.args.split()
                image_name = from_args[0] if from_args else ""
                if image_name.lower() not in stage_aliases:
                    self._check_from_instruction(dockerfile_path, instruction, arg_defaults)
                if len(from_args) >= 3 and from_args[1].lower() == "as":
                    stage_aliases.add(from_args[2].lower())

        return self.violations

    @staticmethod
    def _resolve_args(image_name: str, arg_defaults: Dict[str, str]) -> str:
        """Best-effort substitution of ${VAR}/$VAR using known ARG defaults."""
        def substitute(match):
            var_name = match.group(1) or match.group(2)
            return arg_defaults.get(var_name, match.group(0))

        return re.sub(r'\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)', substitute, image_name)
    
    def check_docker_compose(self, context: Dict[str, Any]) -> None:
        """Check docker-compose for latest image tags"""
        parsed_data = context.get('parsed_data', {})
        
        if 'services' in parsed_data:
            for service_name, service_config in parsed_data['services'].items():
                if 'image' in service_config:
                    image = service_config['image']
                    if self._is_latest_tag(image):
                        self._add_latest_tag_violation(
                            context.get('file_path'),
                            getattr(service_config, '__line__', 0),
                            image,
                            service_name
                        )
    
    def _check_from_instruction(self, dockerfile_path: str, instruction: DockerfileInstruction,
                                 arg_defaults: Dict[str, str] = None) -> None:
        """Check FROM instruction for latest tag usage"""
        if not instruction.args:
            return

        # Parse image name from FROM instruction
        image_name = instruction.args.split()[0]  # Take first token (ignore AS alias)

        resolved_image_name = self._resolve_args(image_name, arg_defaults or {})

        if self._is_latest_tag(resolved_image_name):
            self._add_latest_tag_violation(
                dockerfile_path,
                instruction,
                image_name
            )
    
    def _is_latest_tag(self, image_name: str) -> bool:
        """Check if image uses latest tag or no tag"""
        # Remove whitespace
        image_name = image_name.strip()
        
        # Check for no tag (no :)
        if ':' not in image_name:
            return True
            
        # Check for explicit latest tag
        if image_name.endswith(':latest'):
            return True
            
        return False
    
    def _add_latest_tag_violation(self, resource_name: str, instruction,
                                  image_name: str, service_name: str = None) -> None:
        """Add a latest tag violation.

        `instruction` is either a DockerfileInstruction (Dockerfile FROM
        case) or a plain int line number (docker-compose service case).
        """

        cve_id = "DOCKER-SEC-001"

        if service_name:
            message = f"Service '{service_name}' uses image with latest/untagged version: '{image_name}'. " \
                     f"Consider using specific version tags for reproducible builds."
        else:
            message = f"FROM instruction uses image with latest/untagged version: '{image_name}'. " \
                     f"Consider using specific version tags for reproducible builds."

        if isinstance(instruction, DockerfileInstruction):
            line_number = instruction.line_number
            instruction_text = str(instruction)
        elif isinstance(instruction, int):
            line_number = instruction
            instruction_text = f"image: {image_name}"
        else:
            line_number = 0
            instruction_text = f"image: {image_name}"
        
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
            image_name=image_name,
            service_name=service_name,
            checker="LatestTagChecker"
        )