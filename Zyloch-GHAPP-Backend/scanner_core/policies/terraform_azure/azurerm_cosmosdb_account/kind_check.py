"""Auto-generated from: policies/terraform/azurerm_cosmosdb_account/kind_check.rego
"""
from scanner_core.core.base import BasePolicy, Violation
from scanner_core.core.messages import COSMOSDB_KIND_UNEXPECTED


class Policy(BasePolicy):
    name = "azurerm_cosmosdb_kind_check"

    def check(self, resource, metadata=None):
        values = resource.get("values", {})
        kind = values.get("kind")
        if kind and kind.lower() not in ("globaldocumentdb", "mongodb", "sql", "table"):
            return [Violation(self.name, COSMOSDB_KIND_UNEXPECTED, resource, params={"kind": kind})]
        return []


def check(resource, metadata=None):
    return Policy().check(resource, metadata)
