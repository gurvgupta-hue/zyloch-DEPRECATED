import re
from typing import Dict, List, Any
from scanner_core.policies.docker.base_checker import BaseDockerSecurityChecker
from scanner_core.models.violation import DockerSecurityViolation
from scanner_core.helpers.docker_helper import DockerfileInstruction
from scanner_core.constants.security_constants import DockerSecurityConstants
from pathlib import Path


class UnallowedCommandsChecker(BaseDockerSecurityChecker):
    """Check for unallowed commands in RUN instructions"""
    
    # Commands that pose security risks
    UNALLOWED_COMMANDS = [
        "apk",
        "apt", 
        "pip",
        "curl",
        "wget",
        "nc",
        "netcat",
        "telnet",
        "ssh",
        "ftp"
    ]
    
    def check(self, contexts: List[Dict[str, Any]]) -> List[DockerSecurityViolation]:
        """Check for unallowed commands in RUN instructions"""
        self.violations = []
        
        for context in contexts:
            if context.get('file_type') == 'Dockerfile':
                instructions = context.get('instruction_objects', [])
                for instruction in instructions:
                    if instruction.instruction.lower() == "run":
                        self._check_run_instruction(context, instruction)

        return self.violations

    def _check_run_instruction(self, context: Dict[str, Any], instruction: DockerfileInstruction) -> None:
        """Check RUN instruction for unallowed commands"""
        if not instruction.args:
            return

        command = instruction.args.lower()

        # Check for unallowed commands as whole tokens (word-boundary match),
        # not raw substrings - otherwise short names like "nc" or "ftp" match
        # inside unrelated words (e.g. "sync", "sftp-client").
        for unallowed_cmd in self.UNALLOWED_COMMANDS:
            if re.search(rf'\b{re.escape(unallowed_cmd)}\b', command):
                self.add_violation(
                    cve_id="DOCKER-SEC-025",
                    severity=DockerSecurityConstants.SEVERITY_HIGH,
                    resource={
                        'file_path': context.get('file_path'),
                        'file_type': 'Dockerfile',
                        'line_number': instruction.line_number
                    },
                    key_path=f"RUN {command[:40]}...",
                    message=f"Unallowed command found: '{unallowed_cmd}'. "
                           f"This command may pose security risks or violate organizational policies.",
                    checker="UnallowedCommandsChecker"
                )
                break  # Only report once per instruction