from abc import ABC, abstractmethod
from typing import Dict, List, Any
from scanner_core.models.violation import PolicyViolation
from scanner_core.helpers.k8s_resource_helper import K8sResourceHelper


class BaseSecurityChecker(ABC):
    """Abstract base class for security policy checkers"""
    
    def __init__(self):
        """Initialize checker with empty violations list"""
        self.violations: List[PolicyViolation] = []
        self.helper = K8sResourceHelper()
    
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
        Add a policy violation to the list.
        
        Args:
            cve_id: CVE identifier
            severity: Violation severity level
            resource: Kubernetes resource that violated policy
            key_path: JSON path to violating field
            message: Human-readable violation message
            metadata: Additional metadata to attach
        """
        violation = PolicyViolation(
            cve_id=cve_id,
            severity=severity,
            resource_name=self.helper.get_resource_name(resource),
            resource_kind=resource.get("kind", "unknown"),
            key_path=key_path,
            message=message,
            metadata=metadata
        )
        self.violations.append(violation)
    
    def should_check_resource(
        self,
        resource: Dict[str, Any],
        allowed_kinds: List[str]
    ) -> bool:
        """
        Determine if resource should be checked.
        
        Args:
            resource: Kubernetes resource dictionary
            allowed_kinds: List of allowed resource kinds
            
        Returns:
            True if resource should be checked
        """
        return resource.get("kind", "") in allowed_kinds
    
    @abstractmethod
    def check(self, resources: List[Dict[str, Any]]) -> List[PolicyViolation]:
        """
        Execute security checks on resources.
        
        Args:
            resources: List of Kubernetes resources
            
        Returns:
            List of policy violations found
        """
        pass
    
    def get_checker_name(self) -> str:
        """Get human-readable checker name"""
        return self.__class__.__name__
