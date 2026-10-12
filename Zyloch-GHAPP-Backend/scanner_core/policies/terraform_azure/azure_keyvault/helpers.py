"""Helper functions for Key Vault policies.

Provides utility functions compatible with Rego helpers used by Key Vault policies.
"""
from typing import Optional

from scanner_core.core.base import Violation


def build_deny_result(resource: dict, key_path: str, message: str) -> Violation:
    """Build a denial result for Key Vault policy violations.
    
    Args:
        resource: Terraform resource dictionary
        key_path: Path to the field causing the violation
        message: Human-readable violation message
        
    Returns:
        Violation object for the policy engine
    """
    return Violation("azure_keyvault_helper", message, resource)
