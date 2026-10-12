"""Auto-generated from: policies/terraform/azurerm_route_table/main.rego
"""
from scanner_core.core.base import BasePolicy, Violation


class Policy(BasePolicy):
    name = "azurerm_route_table_main"

    def check(self, resource, metadata=None):
        # reuse the no_internet_route check where applicable
        from .no_internet_route import check as no_internet
        return no_internet(resource, metadata)


def check(resource, metadata=None):
    return Policy().check(resource, metadata)

