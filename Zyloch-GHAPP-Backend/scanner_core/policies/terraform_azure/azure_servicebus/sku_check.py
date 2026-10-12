"""Auto-generated from: policies/terraform/azure_servicebus/sku_check.rego
"""
from scanner_core.core.base import BasePolicy, Violation
from scanner_core.core.messages import SERVICE_BUS_SKU_MISSING


class Policy(BasePolicy):
    name = "azure_servicebus_sku_check"
    RESOURCE_TYPES = {"azurerm_servicebus_namespace"}

    def check(self, resource, metadata=None):
        if resource.get("type") not in self.RESOURCE_TYPES:
            return []
        values = resource.get("values", {})
        sku = values.get("sku")
        if not sku:
            return [Violation(self.name, SERVICE_BUS_SKU_MISSING, resource)]
        return []


def check(resource, metadata=None):
    return Policy().check(resource, metadata)
