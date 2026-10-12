"""Auto-generated from: policies/terraform/azure_keyvault/soft_delete_retention_days_check.rego
"""
from typing import List, Optional

from scanner_core.core.base import BasePolicy, Violation
from scanner_core.core.messages import SOFT_DELETE_RETENTION_MIN


class Policy(BasePolicy):
    """Policy validator for Azure Key Vault soft delete retention period."""
    
    name = "azure_keyvault_soft_delete_retention_days_check"
    MIN_RETENTION_DAYS = 7

    def check(self, resource: dict, metadata: Optional[dict] = None) -> List[Violation]:
        """Validate that Key Vault soft delete retention is at least 7 days.
        
        Args:
            resource: Terraform resource dictionary
            metadata: Optional metadata dictionary
            
        Returns:
            List of policy violations found
        """
        values = resource.get("values", {})
        days = values.get("soft_delete_retention_days")
        if days is None or int(days) < self.MIN_RETENTION_DAYS:
            return [Violation(self.name, SOFT_DELETE_RETENTION_MIN, resource)]
        return []


def check(resource: dict, metadata: Optional[dict] = None) -> List[Violation]:
    """Check function wrapper for policy validation."""
    return Policy().check(resource, metadata)
