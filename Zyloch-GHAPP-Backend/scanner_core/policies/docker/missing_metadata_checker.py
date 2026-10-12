from typing import Dict, List, Any, Set
from scanner_core.policies.docker.base_checker import BaseDockerSecurityChecker
from scanner_core.models.violation import DockerSecurityViolation
from scanner_core.helpers.docker_helper import DockerfileInstruction
from scanner_core.constants.security_constants import DockerSecurityConstants
from pathlib import Path


class MissingMetadataChecker(BaseDockerSecurityChecker):
    """Check for missing metadata LABEL instructions"""
    
    # Required metadata labels
    REQUIRED_METADATA = [
        "name",
        "version", 
        "source",
        "summary",
        "team"
    ]
    
    def check(self, contexts: List[Dict[str, Any]]) -> List[DockerSecurityViolation]:
        """Check for missing metadata labels"""
        self.violations = []
        
        for context in contexts:
            if context.get('file_type') == 'Dockerfile':
                self._check_dockerfile_metadata(context)

        return self.violations

    def _check_dockerfile_metadata(self, context: Dict[str, Any]) -> None:
        """Check if all required metadata labels are present"""
        instructions = context.get('instruction_objects', [])
        found_labels: Set[str] = set()
        # Not tied to a single instruction - anchor on the last LABEL found,
        # or the last line of the file when there is no LABEL at all.
        last_label_line = instructions[-1].line_number if instructions else 0

        # Extract all LABEL instructions
        for instruction in instructions:
            if instruction.instruction.lower() == "label":
                self._extract_labels_from_instruction(instruction, found_labels)
                last_label_line = instruction.line_number

        # Check for missing required metadata
        missing_labels = set(self.REQUIRED_METADATA) - found_labels

        if missing_labels:
            self.add_violation(
                cve_id="DOCKER-SEC-022",
                severity=DockerSecurityConstants.SEVERITY_LOW,
                resource={
                    'file_path': context.get('file_path'),
                    'file_type': 'Dockerfile',
                    'line_number': last_label_line
                },
                key_path="LABEL metadata",
                message=f"Missing required metadata labels: {', '.join(sorted(missing_labels))}. "
                       f"Consider adding LABEL instructions for better image documentation and compliance.",
                checker="MissingMetadataChecker"
            )
    
    def _extract_labels_from_instruction(self, instruction: DockerfileInstruction, found_labels: Set[str]) -> None:
        """Extract label names from LABEL instruction"""
        if not instruction.args:
            return

        # Handle different LABEL formats:
        # LABEL key=value
        # LABEL key1=value1 key2=value2
        # LABEL "key"="value"
        args = instruction.args.split()

        for arg in args:
            if '=' in arg:
                key = arg.split('=')[0].strip().strip('"\'')
                found_labels.add(key.lower())
            else:
                # Handle space-separated key value pairs
                if len(args) >= 2:
                    key = arg.strip().strip('"\'')
                    found_labels.add(key.lower())