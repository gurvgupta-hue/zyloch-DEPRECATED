"""Aggregator for service bus checks"""
from scanner_core.core.base import BasePolicy, Violation
from .sku_check import check as sku_check

class Policy(BasePolicy):
    name = "azure_servicebus"
    RESOURCE_TYPES = {"azurerm_servicebus_namespace"}

    def check(self, resource, metadata=None):
        if resource.get("type") not in self.RESOURCE_TYPES:
            return []
        res = []
        res.extend(sku_check(resource, metadata))
        return res


def check(resource, metadata=None):
    return Policy().check(resource, metadata)
