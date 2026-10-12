"""Auto-generated from: policies/terraform/azurerm_mssql_database/sku_required.rego
"""
from scanner_core.core.base import BasePolicy, Violation
from scanner_core.core.messages import MSSQL_SKU_REQUIRED


class Policy(BasePolicy):
    name = "azurerm_mssql_database_sku_required"

    def check(self, resource, metadata=None):
        values = resource.get("values", {})
        sku = values.get("sku")
        if not sku:
            return [Violation(self.name, MSSQL_SKU_REQUIRED, resource)]
        return []


def check(resource, metadata=None):
    return Policy().check(resource, metadata)
