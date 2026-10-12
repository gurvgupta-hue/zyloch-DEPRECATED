from typing import Dict, List, Any
from scanner_core.policies.docker.base_checker import BaseDockerSecurityChecker
from scanner_core.models.violation import DockerSecurityViolation
from scanner_core.helpers.docker_helper import DockerfileInstruction
from scanner_core.constants.security_constants import DockerSecurityConstants


class InsecureBaseImageChecker(BaseDockerSecurityChecker):
    """Check for deprecated or insecure base images"""
    
    INSECURE_BASE_IMAGES = DockerSecurityConstants.INSECURE_BASE_IMAGES
    
    def check(self, contexts: List[Dict[str, Any]]) -> List[DockerSecurityViolation]:
        """Check for insecure base images in Docker files"""
        self.reset_violations()
        
        for context in contexts:
            if context.get('file_type') == "Dockerfile":
                self.check_dockerfile(context.get('file_path'), context.get('instruction_objects', []))
        
        return self.violations
    
    def check_dockerfile(self, dockerfile_path: str, instructions: List[DockerfileInstruction]) -> None:
        """Check Dockerfile for insecure base images"""
        
        for instruction in instructions:
            if instruction.instruction.lower() == "from":
                image = instruction.args.strip().lower()
                if any(image.startswith(insecure.lower()) for insecure in self.INSECURE_BASE_IMAGES):
                    self.add_violation(
                        cve_id="DOCKER-SEC-013",
                        severity=DockerSecurityConstants.SEVERITY_MEDIUM,
                        resource={
                            'file_path': dockerfile_path,
                            'file_type': 'Dockerfile',
                            'line_number': instruction.line_number if hasattr(instruction, 'line_number') else 0
                        },
                        key_path="FROM",
                        message=f"Insecure base image detected: {instruction.args.strip()}. Use specific versioned base images.",
                        image=instruction.args.strip()
                    )
    
    def reset_violations(self) -> None:
        """Reset violations list"""
        self.violations = []