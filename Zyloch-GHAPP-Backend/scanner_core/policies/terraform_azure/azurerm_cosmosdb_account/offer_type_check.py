"""Auto-generated from: policies/terraform/azurerm_cosmosdb_account/offer_type_check.rego
"""
from scanner_core.core.base import BasePolicy, Violation
from scanner_core.core.messages import COSMOSDB_OFFER_TYPE_REQUIRED


class Policy(BasePolicy):
    name = "azurerm_cosmosdb_offer_type_check"

    def check(self, resource, metadata=None):
        if resource.get("type") != "azurerm_cosmosdb_account":
            return []
        values = resource.get("values", {})
        offer = values.get("offer_type") or values.get("offerType")
        if offer != "Standard":
            return [Violation(self.name, COSMOSDB_OFFER_TYPE_REQUIRED, resource)]
        return []


def check(resource, metadata=None):
    return Policy().check(resource, metadata)
