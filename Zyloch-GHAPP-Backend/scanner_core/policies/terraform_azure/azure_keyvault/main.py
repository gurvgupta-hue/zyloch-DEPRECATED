"""Auto-generated from: policies/terraform/azure_keyvault/main.rego
"""
from typing import List, Optional

from scanner_core.core.base import BasePolicy, Violation
from .soft_delete_retention_days_check import check as soft_delete_check
from .sku_name_check import check as sku_check
from .network_acls_bypass_check import check as network_acls_check
from .enable_purge_protection_check import check as purge_protection_check


class Policy(BasePolicy):
    """Aggregator policy for azure_keyvault resource checks.
    
    Validates Key Vault security and configuration policies including:
    - Soft delete retention period (minimum 7 days)
    - SKU configuration
    - Network ACLs bypass settings
    - Purge protection enablement
    """
    
    name = "azure_keyvault_main"
    # Only apply to Azure Key Vault resources
    RESOURCE_TYPES = {"azurerm_key_vault"}

    def check(self, resource: dict, metadata: Optional[dict] = None) -> List[Violation]:
        """Validate Key Vault resource against all policy rules.
        
        Args:
            resource: Terraform resource dictionary
            metadata: Optional metadata dictionary
            
        Returns:
            List of policy violations found
        """
        # Only check this resource if it's an Azure Key Vault
        if resource.get("type") not in self.RESOURCE_TYPES:
            return []
        
        violations = []
        violations.extend(soft_delete_check(resource, metadata))
        violations.extend(sku_check(resource, metadata))
        violations.extend(network_acls_check(resource, metadata))
        violations.extend(purge_protection_check(resource, metadata))
        return violations


def check(resource: dict, metadata: Optional[dict] = None) -> List[Violation]:
    """Check function wrapper for policy validation.
    
    Args:
        resource: Terraform resource dictionary
        metadata: Optional metadata dictionary
        
    Returns:
        List of policy violations found
    """
    return Policy().check(resource, metadata)
