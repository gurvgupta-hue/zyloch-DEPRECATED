"""Auto-generated from: policies/terraform/azurerm_service_plan/main.rego
"""
from scanner_core.core.base import BasePolicy, Violation
from . import os_type
from . import sku_name


class Policy(BasePolicy):
    name = "azurerm_service_plan_main"
    RESOURCE_TYPES = {"azurerm_service_plan"}

    def check(self, resource, metadata=None):
        if resource.get("type") not in self.RESOURCE_TYPES:
            return []
        violations = []
        violations.extend(os_type.check(resource, metadata))
        violations.extend(sku_name.check(resource, metadata))
        return violations


def check(resource, metadata=None):
    return Policy().check(resource, metadata)
