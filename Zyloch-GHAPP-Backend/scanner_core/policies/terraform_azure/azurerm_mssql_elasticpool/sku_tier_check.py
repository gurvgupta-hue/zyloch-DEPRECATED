"""Auto-generated from: policies/terraform/azurerm_mssql_elasticpool/sku_tier_check.rego
"""
from scanner_core.core.base import BasePolicy, Violation, IssueType, Severity
from scanner_core.core.messages import MSSQL_ELASTICPOOL_SKU_TIER_INVALID


# Valid tier values for SQL Database elastic pools
VALID_SKU_TIERS = {"Basic", "Standard", "Premium", "GeneralPurpose", "BusinessCritical"}


class Policy(BasePolicy):
    name = "azurerm_mssql_elasticpool_sku_tier_check"

    def check(self, resource, metadata=None):
        values = resource.get("values", {})
        sku = values.get("sku") or {}
        
        if isinstance(sku, dict):
            sku_tier = sku.get("tier", "")
        else:
            # If sku is not a dict, we can't validate tier
            return []
        
        if sku_tier and sku_tier not in VALID_SKU_TIERS:
            return [Violation(
                self.name,
                MSSQL_ELASTICPOOL_SKU_TIER_INVALID.format(tier=sku_tier),
                resource,
                issue_type=IssueType.IncorrectValue,
                severity=Severity.MEDIUM,
                code="AZ-SEC-SQL-006"
            )]
        return []


def check(resource, metadata=None):
    return Policy().check(resource, metadata)
