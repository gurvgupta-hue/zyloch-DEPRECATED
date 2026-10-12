from typing import Dict, List, Any
from scanner_core.policies.docker.base_checker import BaseDockerSecurityChecker
from scanner_core.models.violation import DockerSecurityViolation
from scanner_core.helpers.docker_helper import DockerfileInstruction
from scanner_core.constants.security_constants import DockerSecurityConstants
from pathlib import Path


class PackageUpgradeChecker(BaseDockerSecurityChecker):
    """Check for package upgrade commands in Dockerfile"""
    
    def check(self, contexts: List[Dict[str, Any]]) -> List[DockerSecurityViolation]:
        """Check for package upgrade commands that should be avoided"""
        self.violations = []
        
        for context in contexts:
            if context.get('file_type') == 'Dockerfile':
                instructions = context.get('instruction_objects', [])
                for instruction in instructions:
                    if instruction.instruction.lower() == "run":
                        self._check_run_instruction(context, instruction)

        return self.violations

    def _check_run_instruction(self, context: Dict[str, Any], instruction: DockerfileInstruction) -> None:
        """Check RUN instruction for package upgrade commands"""
        if not instruction.args:
            return

        command = instruction.args
        
        # Check for upgrade commands
        for upgrade_cmd in DockerSecurityConstants.PACKAGE_UPGRADE_COMMANDS:
            if upgrade_cmd in command.lower():
                self.add_violation(
                    cve_id="DOCKER-SEC-008",
                    severity=DockerSecurityConstants.SEVERITY_MEDIUM,
                    resource={
                        'file_path': context.get('file_path'),
                        'file_type': 'Dockerfile',
                        'line_number': instruction.line_number
                    },
                    key_path=f"RUN {command[:50]}...",
                    message=f"Package upgrade command detected: '{upgrade_cmd}'. "
                           f"Package upgrades can introduce vulnerabilities and "
                           f"make builds non-reproducible. Use specific package versions instead.",
                    checker="PackageUpgradeChecker"
                )
                break  # Only report once per instruction