import re
from typing import Dict, List, Any
from scanner_core.policies.docker.base_checker import BaseDockerSecurityChecker
from scanner_core.models.violation import DockerSecurityViolation
from scanner_core.helpers.docker_helper import DockerfileInstruction
from scanner_core.constants.security_constants import DockerSecurityConstants
from pathlib import Path


class UnallowedImagesChecker(BaseDockerSecurityChecker):
    """Check for unallowed base images in FROM instructions"""
    
    # Images that are discouraged due to security concerns
    UNALLOWED_IMAGES = [
        "python",
        "node", 
        "ruby",
        "openjdk",
        "ubuntu",
        "debian",
        "centos",
        "alpine"
    ]
    
    def check(self, contexts: List[Dict[str, Any]]) -> List[DockerSecurityViolation]:
        """Check for unallowed base images"""
        self.violations = []
        
        for context in contexts:
            if context.get('file_type') == 'Dockerfile':
                instructions = context.get('instruction_objects', [])
                for instruction in instructions:
                    if instruction.instruction.lower() == "from":
                        self._check_from_instruction(context, instruction)

        return self.violations

    def _check_from_instruction(self, context: Dict[str, Any], instruction: DockerfileInstruction) -> None:
        """Check FROM instruction for unallowed base images"""
        if not instruction.args:
            return

        image_name = instruction.args.split()[0]

        # Extract base image name (before : or @)
        base_image = image_name.split(':')[0].split('@')[0].lower()

        # "distroless" images (gcr.io/distroless/*) are exactly the hardened,
        # minimal alternative this checker is trying to steer people towards -
        # never flag them, regardless of the language they embed.
        if 'distroless' in base_image:
            return

        # Match against the final path segment (the actual repository name,
        # e.g. "nodejs20-debian12" in "gcr.io/distroless/nodejs20-debian12")
        # as a whole word, not a raw substring of the full path - otherwise
        # "node" matches inside unrelated names like "distroless/nodejs".
        repo_segment = base_image.rsplit('/', 1)[-1]

        # Check if the base image is in the unallowed list
        for unallowed in self.UNALLOWED_IMAGES:
            if re.search(rf'\b{re.escape(unallowed)}\b', repo_segment):
                self.add_violation(
                    cve_id="DOCKER-SEC-026",
                    severity=DockerSecurityConstants.SEVERITY_MEDIUM,
                    resource={
                        'file_path': context.get('file_path'),
                        'file_type': 'Dockerfile',
                        'line_number': instruction.line_number
                    },
                    key_path=f"FROM {image_name}",
                    message=f"Unallowed base image found: '{base_image}'. "
                           f"Consider using more secure, minimal, or organization-approved base images.",
                    checker="UnallowedImagesChecker"
                )
                break  # Only report once per instruction