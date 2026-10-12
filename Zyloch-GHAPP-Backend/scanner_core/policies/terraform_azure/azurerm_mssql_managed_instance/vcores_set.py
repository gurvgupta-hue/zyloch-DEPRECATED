"""Auto-generated from: policies/terraform/azurerm_mssql_managed_instance/vcores_set.rego
"""
from scanner_core.core.base import BasePolicy, Violation, IssueType, Severity
from scanner_core.core.messages import MSSQL_MANAGED_INSTANCE_VCORES_INVALID


VALID_VCORES_GEN4 = {8, 16, 24}
VALID_VCORES_GEN5 = {4, 6, 8, 10, 12, 16, 20, 24, 32, 40, 48, 56, 64, 80, 96, 128}


class Policy(BasePolicy):
    name = "azurerm_mssql_managed_instance_vcores_set"

    def check(self, resource, metadata=None):
        values = resource.get("values", {})
        vcores = values.get("vcores")
        sku = values.get("sku") or {}
        
        # Get SKU name
        if isinstance(sku, dict):
            sku_name = sku.get("name", "")
        else:
            sku_name = str(sku) if sku else ""
        
        # Check if vcores is set and is numeric
        if vcores is None:
            return [Violation(
                self.name,
                MSSQL_MANAGED_INSTANCE_VCORES_INVALID,
                resource,
                issue_type=IssueType.MissingValue,
                severity=Severity.MEDIUM
            )]
        
        try:
            vcores_value = int(vcores)
        except (ValueError, TypeError):
            return [Violation(
                self.name,
                MSSQL_MANAGED_INSTANCE_VCORES_INVALID,
                resource,
                issue_type=IssueType.IncorrectValue,
                severity=Severity.MEDIUM
            )]
        
        # Validate vCore values based on SKU
        if sku_name == "GP_Gen4" or sku_name == "BC_Gen4":
            if vcores_value not in VALID_VCORES_GEN4:
                return [Violation(
                    self.name,
                    MSSQL_MANAGED_INSTANCE_VCORES_INVALID,
                    resource,
                    issue_type=IssueType.IncorrectValue,
                    severity=Severity.MEDIUM
                )]
        elif sku_name.startswith("GP_Gen5") or sku_name.startswith("GP_Gen8") or sku_name.startswith("BC_Gen5") or sku_name.startswith("BC_Gen8"):
            if vcores_value not in VALID_VCORES_GEN5:
                return [Violation(
                    self.name,
                    MSSQL_MANAGED_INSTANCE_VCORES_INVALID,
                    resource,
                    issue_type=IssueType.IncorrectValue,
                    severity=Severity.MEDIUM
                )]
        
        return []


def check(resource, metadata=None):
    return Policy().check(resource, metadata)
