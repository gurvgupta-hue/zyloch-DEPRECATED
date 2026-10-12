"""Auto-generated from: policies/terraform/azurerm_eventgrid_namespace/sku_check.rego
"""
from scanner_core.core.base import BasePolicy, Violation, IssueType, Severity
from scanner_core.core.messages import EVENTGRID_SKU_INVALID


class Policy(BasePolicy):
    name = "azurerm_eventgrid_sku_check"

    def check(self, resource, metadata=None):
        values = resource.get("values", {})
        sku = values.get("sku", "")
        allowed_skus = {"Basic", "Standard", "Premium"}
        
        if sku and sku not in allowed_skus:
            return [Violation(
                self.name,
                EVENTGRID_SKU_INVALID.format(allowed=allowed_skus),
                resource,
                issue_type=IssueType.IncorrectValue,
                severity=Severity.MEDIUM,
                code="AZ-SEC-EG-001"
            )]
        return []


def check(resource, metadata=None):
    return Policy().check(resource, metadata)
