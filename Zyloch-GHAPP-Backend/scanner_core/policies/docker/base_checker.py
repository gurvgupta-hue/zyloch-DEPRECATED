# ============================================================================
# FILE: checkers/base_checker.py
# ============================================================================
"""Base class for all Docker security checkers"""

from abc import ABC, abstractmethod
from typing import List, Dict, Any
from scanner_core.models.violation import DockerSecurityViolation
from scanner_core.helpers.docker_helper import DockerHelper


class BaseDockerSecurityChecker(ABC):
    """Abstract base class for Docker security policy checkers"""
    
    def __init__(self):
        """Initialize checker with empty violations list"""
        self.violations: List[DockerSecurityViolation] = []
        self.helper = DockerHelper()
    
    def add_violation(
        self,
        cve_id: str,
        severity: str,
        resource: Dict[str, Any],
        key_path: str,
        message: str,
        **metadata
    ) -> None:
        """
        Add a security policy violation to the list (K8s-compatible signature).
        
        Args:
            cve_id: CVE identifier for this violation type
            severity: Violation severity level
            resource: Docker file resource dictionary being analyzed
            key_path: Path to the specific instruction or field causing violation
            message: Human-readable violation message
            metadata: Additional metadata to attach
        """
        violation = DockerSecurityViolation(
            cve_id=cve_id,
            severity=severity,
            resource_name=resource.get('file_path'),
            resource_type=resource.get('file_type', 'dockerfile'),
            line_number=resource.get('line_number', 0),
            instruction=key_path,
            message=message,
            metadata=metadata
        )
        self.violations.append(violation)
    
    def should_check_file(self, context: Dict[str, Any], supported_types: List[str]) -> bool:
        """
        Check if this file type should be processed by this checker.
        
        Args:
            context: Docker file context dictionary
            supported_types: List of supported file types for this checker
            
        Returns:
            True if file should be checked
        """
        return context.get('file_type') in supported_types
    
    @abstractmethod
    def check(self, contexts: List[Dict[str, Any]]) -> List[DockerSecurityViolation]:
        """
        Perform security check on provided Docker file contexts.
        
        Args:
            contexts: List of Docker file context dictionaries to check
            
        Returns:
            List of security violations found
        """
        pass
    
    def reset_violations(self) -> None:
        """Clear all violations for a fresh check"""
        self.violations = []
    
    def get_violation_count(self) -> int:
        """Get total number of violations found"""
        return len(self.violations)
    
    def get_violations_by_severity(self, severity: str) -> List[DockerSecurityViolation]:
        """
        Get violations filtered by severity level.
        
        Args:
            severity: Severity level to filter by
            
        Returns:
            List of violations matching the severity
        """
        return [v for v in self.violations if v.severity == severity]
    
    def get_violations_by_file(self, file_path: str) -> List[DockerSecurityViolation]:
        """
        Get violations filtered by file path.
        
        Args:
            file_path: File path to filter by
            
        Returns:
            List of violations for the specific file
        """
        return [v for v in self.violations if v.resource_name == file_path]