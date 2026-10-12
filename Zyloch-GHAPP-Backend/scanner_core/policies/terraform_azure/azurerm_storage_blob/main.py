"""Aggregator for azurerm storage blob checks"""
from typing import List, Optional

from scanner_core.core.base import BasePolicy, Violation
from .access_tier_check import check as access_tier_check
from .size_check import check as size_check
from .type_check import check as type_check


class Policy(BasePolicy):
    """Aggregator policy for azurerm_storage_blob resource checks."""
    
    name = "azurerm_storage_blob"
    RESOURCE_TYPES = {"azurerm_storage_blob"}

    def check(self, resource: dict, metadata: Optional[dict] = None) -> List[Violation]:
        if resource.get("type") not in self.RESOURCE_TYPES:
            return []
        """Validate storage blob resource against all policy rules.
        
        Args:
            resource: Terraform resource dictionary
            metadata: Optional metadata dictionary
            
        Returns:
            List of policy violations found
        """
        violations = []
        for fn in (access_tier_check, size_check, type_check):
            violations.extend(fn(resource, metadata))
        return violations


def check(resource: dict, metadata: Optional[dict] = None) -> List[Violation]:
    return Policy().check(resource, metadata)
