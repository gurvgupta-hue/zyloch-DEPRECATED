"""Auto-generated from: policies/terraform/azurerm_mssql_elasticpool/sku_name_check.rego
"""
from scanner_core.core.base import BasePolicy, Violation, IssueType, Severity
from scanner_core.core.messages import MSSQL_ELASTICPOOL_SKU_NAME_INVALID


# Valid DTU and vCore values for SQL Database elastic pools
VALID_SKU_NAMES = {
    # DTU-based SKU names
    "50", "100", "200", "300", "400", "800", "1200", "1600", "2000", "2500", "3000",
    # vCore-based SKU names
    "GP_Gen5_2", "GP_Gen5_4", "GP_Gen5_6", "GP_Gen5_8", "GP_Gen5_10", "GP_Gen5_12",
    "GP_Gen5_14", "GP_Gen5_16", "GP_Gen5_18", "GP_Gen5_20", "GP_Gen5_24", "GP_Gen5_32",
    "GP_Gen5_40", "GP_Gen5_80",
    "BC_Gen5_2", "BC_Gen5_4", "BC_Gen5_6", "BC_Gen5_8", "BC_Gen5_10", "BC_Gen5_12",
    "BC_Gen5_14", "BC_Gen5_16", "BC_Gen5_18", "BC_Gen5_20", "BC_Gen5_24", "BC_Gen5_32",
    "BC_Gen5_40", "BC_Gen5_80"
}


class Policy(BasePolicy):
    name = "azurerm_mssql_elasticpool_sku_name_check"

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
                MSSQL_ELASTICPOOL_SKU_NAME_INVALID.format(name=sku_name),
                resource,
                issue_type=IssueType.IncorrectValue,
                severity=Severity.MEDIUM,
                code="AZ-SEC-SQL-005"
            )]
        return []


def check(resource, metadata=None):
    return Policy().check(resource, metadata)
