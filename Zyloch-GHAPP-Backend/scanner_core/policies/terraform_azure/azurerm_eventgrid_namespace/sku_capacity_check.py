"""Auto-generated from: policies/terraform/azurerm_eventgrid_namespace/sku_capacity_check.rego
"""
from scanner_core.core.base import BasePolicy, Violation, IssueType, Severity
from scanner_core.core.messages import EVENTGRID_CAPACITY_INVALID


class Policy(BasePolicy):
    name = "azurerm_eventgrid_sku_capacity_check"

    def check(self, resource, metadata=None):
        values = resource.get("values", {})
        capacity = values.get("capacity", 0)
        
        try:
            capacity_value = int(capacity) if capacity else 0
        except (ValueError, TypeError):
            capacity_value = 0
        
        if capacity_value < 1:
            return [Violation(
                self.name,
                EVENTGRID_CAPACITY_INVALID,
                resource,
                issue_type=IssueType.IncorrectValue,
                severity=Severity.MEDIUM
            )]
        return []


def check(resource, metadata=None):
    return Policy().check(resource, metadata)
