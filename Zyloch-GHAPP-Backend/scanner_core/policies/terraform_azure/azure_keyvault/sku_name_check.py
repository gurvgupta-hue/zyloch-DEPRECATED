"""Auto-generated from: policies/terraform/azure_keyvault/sku_name_check.rego
"""
from typing import List, Optional

from scanner_core.core.base import BasePolicy, Violation
from scanner_core.core.messages import KEY_VAULT_SKU_MISSING


class Policy(BasePolicy):
    """Policy validator for Azure Key Vault SKU configuration."""
    
    name = "azure_keyvault_sku_name_check"

    def check(self, resource: dict, metadata: Optional[dict] = None) -> List[Violation]:
        """Validate that Key Vault SKU is present and allowed.
        
        Args:
            resource: Terraform resource dictionary
            metadata: Optional metadata dictionary
            
        Returns:
            List of policy violations found
        """
        values = resource.get("values", {})
        sku_name = values.get("sku_name")
        allowed = {"standard", "premium"}
        allowed_str = ", ".join(sorted(allowed))

        # Require a non-empty SKU value
        if not sku_name or not str(sku_name).strip():
            message = f"{KEY_VAULT_SKU_MISSING} (allowed: {allowed_str})"
            return [Violation(self.name, message, resource, code="AZ-SEC-KV-002", params={"allowed": allowed_str})]

        # Require SKU to be in the allowed list
        sku_norm = str(sku_name).strip().lower()
        if sku_norm not in allowed:
            message = f"{KEY_VAULT_SKU_MISSING} (allowed: {allowed_str})"
            return [Violation(self.name, message, resource, code="AZ-SEC-KV-002", params={"allowed": allowed_str, "sku": sku_name})]

        return []


def check(resource: dict, metadata: Optional[dict] = None) -> List[Violation]:
    """Check function wrapper for policy validation."""
    return Policy().check(resource, metadata)
