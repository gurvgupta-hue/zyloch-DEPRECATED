"""Auto-generated from: policies/terraform/azurerm_storageaccount/access_tier_check.rego
"""
from typing import List
from scanner_core.core.base import BasePolicy, Violation
from scanner_core.core.messages import STORAGE_ACCOUNT_ACCESS_TIER_INVALID


class Policy(BasePolicy):
    name = "azurerm_storageaccount_access_tier_check"

    def check(self, resource, metadata=None) -> List[Violation]:
        ALLOWED_ACCESS_TIERS = {"Hot", "Cool", "Cold", "Premium"}
        
        values = resource.get("values", {})
        account_kind = values.get("account_kind", "StorageV2")
        
        # Validate only if kind supports access_tier
        if account_kind not in {"BlobStorage", "FileStorage", "StorageV2"}:
            return []
        
        # Check if access_tier is explicitly set
        access_tier = values.get("access_tier")
        if access_tier is None:
            return []
        
        # Validate value
        if access_tier not in ALLOWED_ACCESS_TIERS:
            allowed_str = ", ".join(sorted(ALLOWED_ACCESS_TIERS))
            return [Violation(
                self.name, 
                STORAGE_ACCOUNT_ACCESS_TIER_INVALID, 
                resource, 
                params={"allowed": allowed_str}
            )]
        
        return []


def check(resource, metadata=None):
    return Policy().check(resource, metadata)
