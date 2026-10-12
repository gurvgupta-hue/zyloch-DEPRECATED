"""Auto-generated from: policies/terraform/azurerm_storageaccount/soft_delete_enabled_check.rego.txt
"""
from scanner_core.core.base import BasePolicy, Violation
from scanner_core.core.messages import STORAGE_SOFT_DELETE_REQUIRED


class Policy(BasePolicy):
    name = "azurerm_storageaccount_soft_delete_enabled_check"

    def check(self, resource, metadata=None):
        values = resource.get("values", {})
        delete_retention = values.get("soft_delete_enabled") or values.get("delete_retention")
        if delete_retention is False:
            return [Violation(self.name, STORAGE_SOFT_DELETE_REQUIRED, resource)]
        return []


def check(resource, metadata=None):
    return Policy().check(resource, metadata)
