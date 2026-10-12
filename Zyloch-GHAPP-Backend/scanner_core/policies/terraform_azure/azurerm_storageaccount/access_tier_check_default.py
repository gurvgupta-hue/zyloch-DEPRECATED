"""Auto-generated from: policies/terraform/azurerm_storageaccount/access_tier_check_default.rego
"""
from typing import List
from scanner_core.core.base import BasePolicy, Violation
from scanner_core.core.messages import STORAGE_ACCOUNT_ACCESS_TIER_NOT_ALLOWED


class Policy(BasePolicy):
    name = "azurerm_storageaccount_access_tier_check_default"

    def check(self, resource, metadata=None) -> List[Violation]:
        values = resource.get("values", {})
        account_kind = values.get("account_kind", "StorageV2")
        access_tier = values.get("access_tier")
        
        # access_tier should NOT be set for account_kind not in {BlobStorage, FileStorage, StorageV2}
        if access_tier is not None and account_kind not in {"BlobStorage", "FileStorage", "StorageV2"}:
            return [Violation(
                self.name, 
                STORAGE_ACCOUNT_ACCESS_TIER_NOT_ALLOWED, 
                resource
            )]
        
        return []


def check(resource, metadata=None):
    return Policy().check(resource, metadata)
