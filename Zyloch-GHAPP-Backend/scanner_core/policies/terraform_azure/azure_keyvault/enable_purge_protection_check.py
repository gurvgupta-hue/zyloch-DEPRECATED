"""Auto-generated from: policies/terraform/azure_keyvault/enable_purge_protection_check.rego
"""
from typing import List, Optional

from scanner_core.core.base import BasePolicy, Violation
from scanner_core.core.messages import KEY_VAULT_PURGE_PROTECTION


class Policy(BasePolicy):
    """Policy validator for Azure Key Vault purge protection."""
    
    name = "azure_keyvault_enable_purge_protection_check"

    def check(self, resource: dict, metadata: Optional[dict] = None) -> List[Violation]:
        """Validate that Key Vault has purge protection enabled.
        
        Args:
            resource: Terraform resource dictionary
            metadata: Optional metadata dictionary
            
        Returns:
            List of policy violations found
        """
        values = resource.get("values", {})
        if not values.get("purge_protection_enabled"):
            return [Violation(self.name, KEY_VAULT_PURGE_PROTECTION, resource)]
        return []


def check(resource: dict, metadata: Optional[dict] = None) -> List[Violation]:
    """Check function wrapper for policy validation."""
    return Policy().check(resource, metadata)
