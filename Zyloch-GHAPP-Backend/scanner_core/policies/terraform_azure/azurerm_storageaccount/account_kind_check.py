"""Auto-generated from: policies/terraform/azurerm_storageaccount/account_kind_check.rego
"""
from typing import List
from scanner_core.core.base import BasePolicy, Violation
from scanner_core.core.messages import STORAGE_ACCOUNT_KIND_INVALID


class Policy(BasePolicy):
    name = "azurerm_storageaccount_kind_check"

    def check(self, resource, metadata=None) -> List[Violation]:
        ALLOWED_KINDS = {
            "BlobStorage",
            "BlockBlobStorage",
            "FileStorage",
            "Storage",
            "StorageV2"
        }
        
        values = resource.get("values", {})
        account_kind = values.get("account_kind", "StorageV2")
        
        if account_kind not in ALLOWED_KINDS:
            allowed_str = ", ".join(sorted(ALLOWED_KINDS))
            return [Violation(
                self.name, 
                STORAGE_ACCOUNT_KIND_INVALID, 
                resource,
                params={"allowed": allowed_str}
            )]
        
        return []


def check(resource, metadata=None):
    return Policy().check(resource, metadata)
