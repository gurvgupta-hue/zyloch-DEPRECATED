"""Auto-generated from: policies/terraform/azurerm_storageaccount/account_tier_check.rego.txt
"""
from typing import List
from scanner_core.core.base import BasePolicy, Violation
from scanner_core.core.messages import (
    STORAGE_ACCOUNT_TIER_REQUIRED,
    STORAGE_ACCOUNT_TIER_INVALID,
    STORAGE_ACCOUNT_TIER_PREMIUM_REQUIRED
)


class Policy(BasePolicy):
    name = "azurerm_storageaccount_tier_check"

    def check(self, resource, metadata=None) -> List[Violation]:
        ALLOWED_TIERS = {"Standard", "Premium"}
        violations = []
        
        values = resource.get("values", {})
        account_tier = values.get("account_tier", "")
        account_kind = values.get("account_kind", "StorageV2")
        
        # Check if required and present
        if account_tier == "":
            return [Violation(
                self.name, 
                STORAGE_ACCOUNT_TIER_REQUIRED, 
                resource
            )]
        
        # Check if value is valid
        if account_tier not in ALLOWED_TIERS:
            allowed_str = ", ".join(sorted(ALLOWED_TIERS))
            violations.append(Violation(
                self.name, 
                STORAGE_ACCOUNT_TIER_INVALID, 
                resource,
                params={"allowed": allowed_str}
            ))
        
        # For BlockBlobStorage and FileStorage, tier must be Premium
        if account_kind in {"BlockBlobStorage", "FileStorage"} and account_tier != "Premium":
            violations.append(Violation(
                self.name, 
                STORAGE_ACCOUNT_TIER_PREMIUM_REQUIRED, 
                resource
            ))
        
        return violations


def check(resource, metadata=None):
    return Policy().check(resource, metadata)
