"""Aggregator for azurerm load balancer checks"""
from scanner_core.core.base import BasePolicy, Violation
from .frontend_ip_configuration import check as frontend_check

class Policy(BasePolicy):
    name = "azurerm_load_balancer"
    RESOURCE_TYPES = {"azurerm_lb"}

    def check(self, resource, metadata=None):
        if resource.get("type") not in self.RESOURCE_TYPES:
            return []
        res = []
        res.extend(frontend_check(resource, metadata))
        return res


def check(resource, metadata=None):
    return Policy().check(resource, metadata)
