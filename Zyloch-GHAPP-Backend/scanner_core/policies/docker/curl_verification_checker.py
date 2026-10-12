from typing import Dict, List, Any
from scanner_core.policies.docker.base_checker import BaseDockerSecurityChecker
from scanner_core.models.violation import DockerSecurityViolation
from scanner_core.helpers.docker_helper import DockerfileInstruction
from scanner_core.constants.security_constants import DockerSecurityConstants


class CurlVerificationChecker(BaseDockerSecurityChecker):
    """Check for curl commands without certificate verification"""
    
    def check(self, contexts: List[Dict[str, Any]]) -> List[DockerSecurityViolation]:
        """Check for insecure curl usage in Docker files"""
        self.reset_violations()
        
        for context in contexts:
            if context.get('file_type') == "Dockerfile":
                self.check_dockerfile(context.get('file_path'), context.get('instruction_objects', []))
        
        return self.violations
    
    def check_dockerfile(self, dockerfile_path: str, instructions: List[DockerfileInstruction]) -> None:
        """Check Dockerfile for insecure curl usage"""
        
        for instruction in instructions:
            if instruction.instruction.lower() == "run":
                cmd = instruction.args.lower()
                if 'curl' in cmd:
                    # curl verifies TLS certificates by default; -k/--insecure is
                    # what *disables* that verification. Flag only when one of
                    # those flags is actually present - a plain `curl https://...`
                    # call is already secure and must not be flagged.
                    has_insecure_flag = '--insecure' in cmd.split() or any(
                        tok.startswith('-') and not tok.startswith('--') and 'k' in tok[1:]
                        for tok in cmd.split()
                    )
                    if has_insecure_flag:
                        self.add_violation(
                            cve_id="DOCKER-SEC-019",
                            severity=DockerSecurityConstants.SEVERITY_MEDIUM,
                            resource={
                                'file_path': dockerfile_path,
                                'file_type': 'Dockerfile',
                                'line_number': instruction.line_number if hasattr(instruction, 'line_number') else 0
                            },
                            key_path="RUN",
                            message=f"Curl command disables certificate verification (-k/--insecure). Remove this flag.",
                            command=instruction.args
                        )
    
    def reset_violations(self) -> None:
        """Reset violations list"""
        self.violations = []