from typing import Dict, List, Any
from scanner_core.policies.docker.base_checker import BaseDockerSecurityChecker
from scanner_core.models.violation import DockerSecurityViolation
from scanner_core.helpers.docker_helper import DockerfileInstruction
from scanner_core.constants.security_constants import DockerSecurityConstants


class MultistageBuildChecker(BaseDockerSecurityChecker):
    """Check for multi-stage Dockerfile builds"""
    
    def check(self, contexts: List[Dict[str, Any]]) -> List[DockerSecurityViolation]:
        """Check for multi-stage builds in Docker files"""
        self.reset_violations()
        
        for context in contexts:
            if context.get('file_type') == "Dockerfile":
                self.check_dockerfile(context.get('file_path'), context.get('instruction_objects', []))
        
        return self.violations
    
    def check_dockerfile(self, dockerfile_path: str, instructions: List[DockerfileInstruction]) -> None:
        """Check Dockerfile for multi-stage build usage"""
        
        # Count FROM instructions and RUN instructions
        from_instructions = [inst for inst in instructions if inst.instruction.lower() == "from"]
        from_count = len(from_instructions)
        run_count = sum(1 for inst in instructions if inst.instruction.lower() == "run")
        
        # If single FROM and multiple RUN instructions, suggest multi-stage build
        if from_count == 1 and run_count > 0:
            # Check if it contains build-related commands that could be optimized
            has_build_commands = any(
                keyword in ' '.join(inst.args.lower() for inst in instructions if inst.instruction.lower() == "run")
                for keyword in ['npm install', 'pip install', 'make', 'gcc', 'g++', 'apt-get install', 'yum install']
            )
            
            if has_build_commands:
                self.add_violation(
                    cve_id="DOCKER-SEC-018",
                    severity=DockerSecurityConstants.SEVERITY_LOW,
                    resource={
                        'file_path': dockerfile_path,
                        'file_type': 'Dockerfile',
                        'line_number': from_instructions[0].line_number if from_instructions else 0
                    },
                    key_path="FROM",
                    message="Single-stage build detected. Consider using multi-stage builds to reduce image size and improve security."
                )
    
    def reset_violations(self) -> None:
        """Reset violations list"""
        self.violations = []