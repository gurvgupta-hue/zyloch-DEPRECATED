"""Auto-generated from: policies/terraform/azurerm_cosmosdb_account/consistency_values_check.rego
"""
from scanner_core.core.base import BasePolicy, Violation


class Policy(BasePolicy):
    name = "azurerm_cosmosdb_consistency_values_check"

    def check(self, resource, metadata=None):
        return []
        if resource.get("type") != "azurerm_cosmosdb_account":
            return []
        values = resource.get("values", {})
        cps = values.get("consistency_policy") or []
        allowed_levels = ["Eventual", "Session", "BoundedStaleness", "Strong", "ConsistentPrefix"]
        for cp in (cps if isinstance(cps, list) else [cps]):
            if not isinstance(cp, dict):
                continue
            consistency_level = cp.get("consistency_level") or cp.get("consistencyLevel") or ""
            if consistency_level not in allowed_levels:
                allowed_str = ", ".join(allowed_levels)
                return [Violation(self.name, COSMOSDB_CONSISTENCY_LEVEL_INVALID, resource, params={"allowed": allowed_str})]
        return []


def check(resource, metadata=None):
    return Policy().check(resource, metadata)
