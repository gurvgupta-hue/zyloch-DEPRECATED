from typing import Dict, List, Any
from scanner_core.policies.docker.base_checker import BaseDockerSecurityChecker
from scanner_core.models.violation import DockerSecurityViolation
from scanner_core.helpers.docker_helper import DockerfileInstruction
from scanner_core.constants.security_constants import DockerSecurityConstants
from pathlib import Path


class AddVsCopyChecker(BaseDockerSecurityChecker):
    """Check for ADD command instead of COPY command"""
    
    def check(self, contexts: List[Dict[str, Any]]) -> List[DockerSecurityViolation]:
        """Check for ADD instruction usage that should be COPY"""
        self.violations = []
        
        for context in contexts:
            if context.get('file_type') == 'Dockerfile':
                instructions = context.get('instruction_objects', [])
                for instruction in instructions:
                    if instruction.instruction.lower() == "add":
                        self._check_add_instruction(context, instruction)

        return self.violations

    def _check_add_instruction(self, context: Dict[str, Any], instruction: DockerfileInstruction) -> None:
        """Check ADD instruction and suggest COPY alternative"""
        if not instruction.args:
            return

        command = instruction.args

        # ADD should only be used for extracting archives or downloading from URLs
        # For local files, COPY is preferred. Skip leading --chown=/--chmod=/
        # --from= flags so `source` resolves to the actual source argument.
        args_tokens = [t for t in instruction.args.split() if not t.startswith('--')]
        source = args_tokens[0] if args_tokens else ""

        archive_extensions = (
            '.tar', '.tar.gz', '.tgz', '.tar.bz2', '.tbz2', '.tar.xz', '.txz',
            '.tar.zst', '.tar.Z', '.zip',
        )

        # If source doesn't look like URL or archive, suggest COPY
        if not (source.startswith(('http://', 'https://')) or
                source.endswith(archive_extensions)):
                
            self.add_violation(
                cve_id="DOCKER-SEC-007",
                severity=DockerSecurityConstants.SEVERITY_MEDIUM,
                resource={
                    'file_path': context.get('file_path'),
                    'file_type': 'Dockerfile',
                    'line_number': instruction.line_number
                },
                key_path=f"ADD {command[:40]}...",
                message=f"Use COPY instruction instead of ADD: '{command}'. "
                       f"ADD has additional features like auto-extraction that can be "
                       f"security risks. Use COPY for simple file copying.",
                checker="AddVsCopyChecker"
            )