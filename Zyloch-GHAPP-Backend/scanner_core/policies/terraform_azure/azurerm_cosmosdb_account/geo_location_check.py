"""Auto-generated from: policies/terraform/azurerm_cosmosdb_account/geo_location_check.rego
"""
from scanner_core.core.base import BasePolicy, Violation
from scanner_core.core.messages import COSMOSDB_GEO_LOCATION_REQUIRED


class Policy(BasePolicy):
    name = "azurerm_cosmosdb_geo_location_check"

    def check(self, resource, metadata=None):
        if resource.get("type") != "azurerm_cosmosdb_account":
            return []
        values = resource.get("values", {})
        locations = values.get("geo_location") or []
        # geo_location may be a list; require at least one entry
        if not locations or (isinstance(locations, list) and len(locations) == 0):
            return [Violation(self.name, COSMOSDB_GEO_LOCATION_REQUIRED, resource)]
        return []


def check(resource, metadata=None):
    return Policy().check(resource, metadata)
