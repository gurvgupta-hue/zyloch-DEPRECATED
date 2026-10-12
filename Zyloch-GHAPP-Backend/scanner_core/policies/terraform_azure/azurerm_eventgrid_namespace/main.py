"""Auto-generated from: policies/terraform/azurerm_eventgrid_namespace/main.rego
"""
from scanner_core.core.base import BasePolicy, Violation
from . import sku_check
from . import sku_capacity_check
from . import identity_type_check


class Policy(BasePolicy):
    name = "azurerm_eventgrid_main"
    RESOURCE_TYPES = {"azurerm_eventgrid_namespace"}

    def check(self, resource, metadata=None):
        if resource.get("type") not in self.RESOURCE_TYPES:
            return []
        violations = []
        violations.extend(sku_check.check(resource, metadata))
        violations.extend(sku_capacity_check.check(resource, metadata))
        violations.extend(identity_type_check.check(resource, metadata))
        return violations


def check(resource, metadata=None):
    return Policy().check(resource, metadata)
