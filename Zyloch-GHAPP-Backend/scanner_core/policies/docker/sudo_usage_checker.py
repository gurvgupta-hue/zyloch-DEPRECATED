import re
from typing import Dict, List, Any
from scanner_core.policies.docker.base_checker import BaseDockerSecurityChecker
from scanner_core.models.violation import DockerSecurityViolation
from scanner_core.helpers.docker_helper import DockerfileInstruction
from scanner_core.constants.security_constants import DockerSecurityConstants
from pathlib import Path


class SudoUsageChecker(BaseDockerSecurityChecker):
    """Check for sudo usage in RUN commands"""
    
    def check(self, contexts: List[Dict[str, Any]]) -> List[DockerSecurityViolation]:
        """Check for sudo usage that should be avoided"""
        self.violations = []
        
        for context in contexts:
            if context.get('file_type') == 'Dockerfile':
                instructions = context.get('instruction_objects', [])
                for instruction in instructions:
                    if instruction.instruction.lower() == "run":
                        self._check_run_instruction(context, instruction)

        return self.violations

    def _check_run_instruction(self, context: Dict[str, Any], instruction: DockerfileInstruction) -> None:
        """Check RUN instruction for sudo usage"""
        if not instruction.args:
            return

        command = instruction.args

        # Check for actual sudo invocations: "sudo" as the leading token of a
        # shell statement (split on &&/;/|). A plain substring match also
        # fires on unrelated commands that merely mention the word "sudo"
        # (e.g. `groupadd sudo`), which is not a privilege escalation.
        statements = re.split(r'&&|;|\|\|?', command.lower())
        if any(re.match(r'^\s*sudo\b', stmt) for stmt in statements):
            self.add_violation(
                cve_id="DOCKER-SEC-024",
                severity=DockerSecurityConstants.SEVERITY_HIGH,
                resource={
                    'file_path': context.get('file_path'),
                    'file_type': 'Dockerfile',
                    'line_number': instruction.line_number
                },
                key_path=f"RUN {command[:40]}...",
                message=f"Avoid using 'sudo' command: '{command}'. "
                       f"Containers should run with appropriate user permissions "
                       f"instead of escalating privileges with sudo.",
                checker="SudoUsageChecker"
            )