"""Auto-generated from: policies/terraform/azurerm_cosmosdb_account/enable_automatic_failover_check.rego
"""
from scanner_core.core.base import BasePolicy, Violation
from scanner_core.core.messages import AUTOMATIC_FAILOVER_REQUIRED


class Policy(BasePolicy):
    name = "azurerm_cosmosdb_enable_automatic_failover_check"

    def check(self, resource, metadata=None):
        values = resource.get("values", {})
        auto_failover = values.get("enable_automatic_failover") or values.get("automatic_failover")
        if auto_failover is not True:
            return [Violation(self.name, AUTOMATIC_FAILOVER_REQUIRED, resource)]
        return []


def check(resource, metadata=None):
    return Policy().check(resource, metadata)
