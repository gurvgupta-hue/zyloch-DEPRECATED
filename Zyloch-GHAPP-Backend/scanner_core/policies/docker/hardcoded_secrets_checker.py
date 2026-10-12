from typing import Dict, List, Any
from scanner_core.policies.docker.base_checker import BaseDockerSecurityChecker
from scanner_core.models.violation import DockerSecurityViolation
from scanner_core.helpers.docker_helper import DockerfileInstruction
from scanner_core.constants.security_constants import DockerSecurityConstants
from pathlib import Path
import re


class HardcodedSecretsChecker(BaseDockerSecurityChecker):
    """Check for hardcoded secrets in COPY/ADD commands"""
    
    # Patterns that suggest secret files. Word-boundary anchored so they match
    # whole words (e.g. "secret", "key") rather than any substring - otherwise
    # names like "keycloak-config" or "certbot-renew.sh" get flagged just for
    # containing "key"/"cert" as part of an unrelated word.
    SECRET_FILE_PATTERNS = [
        r"\bsecret\b",
        r"\bkey\b",
        r"\bpassword\b",
        r"\btoken\b",
        r"\bcredential\b",
        r"\bcert\b",
        r"\.pem$",
        r"\.p12$",
        r"\.pfx$",
        r"\.key$",
        r"\.crt$",
        r"^\.ssh/",
    ]
    
    def check(self, contexts: List[Dict[str, Any]]) -> List[DockerSecurityViolation]:
        """Check for hardcoded secrets in COPY/ADD commands"""
        self.violations = []
        
        for context in contexts:
            if context.get('file_type') == 'Dockerfile':
                instructions = context.get('instruction_objects', [])
                for instruction in instructions:
                    if instruction.instruction.lower() in ["copy", "add"]:
                        self._check_copy_add_instruction(context, instruction)

        return self.violations

    def _check_copy_add_instruction(self, context: Dict[str, Any], instruction: DockerfileInstruction) -> None:
        """Check COPY/ADD instruction for potential secret files"""
        if not instruction.args:
            return

        # Check all source arguments (last argument is destination)
        arg_list = instruction.args.split()
        sources = arg_list[:-1] if len(arg_list) > 1 else arg_list
        
        for source in sources:
            if source.startswith('--'):
                # --from=/--chown=/--chmod= flags, not a source path
                continue
            source_lower = source.lower()
            basename_lower = source_lower.rstrip('/').split('/')[-1]

            # Check against secret file patterns. Word/extension patterns are
            # matched against the basename only, so a secret-sounding parent
            # directory (e.g. "credentials-service/app.py") doesn't flag an
            # unrelated file.
            for pattern in self.SECRET_FILE_PATTERNS:
                if re.search(pattern, basename_lower) or re.search(pattern, source_lower):
                    self.add_violation(
                        cve_id="DOCKER-SEC-009",
                        severity=DockerSecurityConstants.SEVERITY_HIGH,
                        resource={
                            'file_path': context.get('file_path'),
                            'file_type': 'Dockerfile',
                            'line_number': instruction.line_number
                        },
                        key_path=f"{instruction.instruction.upper()} {source}",
                        message=f"Potential secret file in {instruction.instruction.upper()} command: '{source}'. "
                               f"Avoid copying secret files directly into container images. "
                               f"Use runtime secret injection instead.",
                        checker="HardcodedSecretsChecker"
                    )
                    break  # Only report once per source file