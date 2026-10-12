from typing import Dict, List, Any
from scanner_core.policies.docker.base_checker import BaseDockerSecurityChecker
from scanner_core.models.violation import DockerSecurityViolation
from scanner_core.helpers.docker_helper import DockerfileInstruction
from scanner_core.constants.security_constants import DockerSecurityConstants


class UnnecessaryServicesChecker(BaseDockerSecurityChecker):
    """Check for unnecessary services in containers"""
    
    UNNECESSARY_SERVICES = {
        'sshd', 'ssh', 'crond', 'cron', 'httpd', 'apache2', 'nginx',
        'vsftpd', 'telnetd', 'bind', 'rsync', 'snmpd'
    }
    
    def check(self, contexts: List[Dict[str, Any]]) -> List[DockerSecurityViolation]:
        """Check for unnecessary services in Docker files"""
        self.reset_violations()
        
        for context in contexts:
            if context.get('file_type') == "Dockerfile":
                self.check_dockerfile(context.get('file_path'), context.get('instruction_objects', []))
        
        return self.violations
    
    def check_dockerfile(self, dockerfile_path: str, instructions: List[DockerfileInstruction]) -> None:
        """Check Dockerfile for unnecessary services"""

        # Only the final build stage actually ships in the resulting image; a
        # RUN in an earlier builder stage (e.g. temporarily installing a
        # package to compile something) is discarded and never present or
        # running in production, so it must not be evaluated. See the same
        # rationale in RootUserChecker.
        last_stage_instructions = instructions
        from_indices = [i for i, inst in enumerate(instructions) if inst.instruction.lower() == "from"]
        if len(from_indices) > 1:
            last_stage_instructions = instructions[from_indices[-1]:]

        # A service that is the image's declared main process (CMD/ENTRYPOINT)
        # is the intended purpose of the container, not an "unnecessary" extra
        # service running alongside it (e.g. a dedicated nginx web-server image).
        main_process_cmd = " ".join(
            instruction.args.lower()
            for instruction in last_stage_instructions
            if instruction.instruction.lower() in ("cmd", "entrypoint")
        )

        for instruction in last_stage_instructions:
            if instruction.instruction.lower() == "run":
                cmd = instruction.args.lower()
                for service in self.UNNECESSARY_SERVICES:
                    if service in main_process_cmd:
                        continue
                    if service in cmd:
                        # Check if it's installing or starting the service
                        if any(keyword in cmd for keyword in ['install', 'start', 'service', 'systemctl', '/etc/init.d']):
                            self.add_violation(
                                cve_id="DOCKER-SEC-020",
                                severity=DockerSecurityConstants.SEVERITY_MEDIUM,
                                resource={
                                    'file_path': dockerfile_path,
                                    'file_type': 'Dockerfile',
                                    'line_number': instruction.line_number if hasattr(instruction, 'line_number') else 0
                                },
                                key_path="RUN",
                                message=(
                                    f"Final image installs/enables the background service '{service}', which "
                                    f"is not the container's declared main process (CMD/ENTRYPOINT). Containers "
                                    f"should run a single foreground process; drop this service or move its "
                                    f"installation to a discarded build stage if it is only needed at build time."
                                ),
                                service=service,
                                command=instruction.args
                            )
    
    def reset_violations(self) -> None:
        """Reset violations list"""
        self.violations = []