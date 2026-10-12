"""Auto-generated from: policies/terraform/azurerm_cosmosdb_account/consistency_policy_check.rego
"""
from scanner_core.core.base import BasePolicy, Violation
from scanner_core.core.messages import COSMOSDB_CONSISTENCY_POLICY_REQUIRED


class Policy(BasePolicy):
    name = "azurerm_cosmosdb_consistency_policy_check"

    def check(self, resource, metadata=None):
        if resource.get("type") != "azurerm_cosmosdb_account":
            return []
        values = resource.get("values", {})
        cp = values.get("consistency_policy") or []
        # if missing or empty
        if not cp:
            return [Violation(self.name, COSMOSDB_CONSISTENCY_POLICY_REQUIRED, resource)]
        return []


def check(resource, metadata=None):
    return Policy().check(resource, metadata)
