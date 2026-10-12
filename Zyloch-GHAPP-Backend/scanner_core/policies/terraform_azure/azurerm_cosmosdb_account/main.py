"""Auto-generated from: policies/terraform/azurerm_cosmosdb_account/main.rego
"""
from scanner_core.core.base import BasePolicy, Violation


class Policy(BasePolicy):
    name = "azurerm_cosmosdb_main"

    def check(self, resource, metadata=None):
        if resource.get("type") != "azurerm_cosmosdb_account":
            return []

        checks = [
            "scanner_core.policies.terraform.azurerm_cosmosdb_account.consistency_policy_check",
            "scanner_core.policies.terraform.azurerm_cosmosdb_account.consistency_values_check",
            "scanner_core.policies.terraform.azurerm_cosmosdb_account.geo_location_check",
            "scanner_core.policies.terraform.azurerm_cosmosdb_account.offer_type_check",
        ]
        violations = []
        for mod in checks:
            m = __import__(mod, fromlist=["check"]) 
            try:
                violations.extend(m.check(resource, metadata))
            except Exception:
                continue
        return violations


def check(resource, metadata=None):
    return Policy().check(resource, metadata)
