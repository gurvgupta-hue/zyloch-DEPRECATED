"""Auto-generated from: policies/terraform/azurerm_mssql_managed_instance/sku_name.rego
"""
from scanner_core.core.base import BasePolicy, Violation, IssueType, Severity
from scanner_core.core.messages import MSSQL_MANAGED_INSTANCE_SKU_NAME_INVALID


VALID_SKU_NAMES = {
    "GP_Gen4", "GP_Gen5", "GP_Gen8IM", "GP_Gen8IH",
    "BC_Gen4", "BC_Gen5", "BC_Gen8IM", "BC_Gen8IH"
}


class Policy(BasePolicy):
    name = "azurerm_mssql_managed_instance_sku_name"

    def check(self, resource, metadata=None):
        values = resource.get("values", {})
        sku = values.get("sku") or {}
        
        if isinstance(sku, dict):
            sku_name = sku.get("name", "")
        else:
            sku_name = str(sku) if sku else ""
        
        if sku_name and sku_name not in VALID_SKU_NAMES:
            return [Violation(
                self.name,
                MSSQL_MANAGED_INSTANCE_SKU_NAME_INVALID.format(allowed=", ".join(sorted(VALID_SKU_NAMES))),
                resource,
                issue_type=IssueType.IncorrectValue,
                severity=Severity.MEDIUM,
                code="AZ-SEC-SQL-008"
            )]
        return []


def check(resource, metadata=None):
    return Policy().check(resource, metadata)
