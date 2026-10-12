"""
Base Security Checker for AWS

All AWS security checkers inherit from this base class.
Provides common functionality for policy validation and violation reporting.
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Any
from scanner_core.models.violation import AWSPolicyViolation


class AWSSecurityChecker(ABC):
    """
    Abstract base class for AWS security checkers.
    
    All AWS security checkers must implement:
    - check(resources: dict) -> List[AWSPolicyViolation]: Execute all security validations
    
    Follows same pattern as GCP checkers for consistency across platforms.
    """

    @abstractmethod
    def check(self, resources: Dict[str, Any]) -> List[AWSPolicyViolation]:
        """
        Execute security validation on provided resources.
        
        Args:
            resources: Dictionary of Terraform resources grouped by type
            
        Returns:
            List of AWSPolicyViolation objects representing security issues found
        """
        pass
    
    POLICY_PREFIX = "AWS-SEC"
    
    def __init__(self):
        """Initialize AWS Security Checker (no-args constructor like GCP)."""
        pass
