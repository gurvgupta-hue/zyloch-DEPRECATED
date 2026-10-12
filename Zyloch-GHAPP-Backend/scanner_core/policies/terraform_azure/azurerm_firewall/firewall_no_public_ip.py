"""Auto-generated from: policies/terraform/azurerm_firewall/firewall_no_public_ip.rego.txt
"""
from scanner_core.core.base import BasePolicy, Violation


class Policy(BasePolicy):
    name = "azurerm_firewall_no_public_ip"

    def check(self, resource, metadata=None):
        return []


def check(resource, metadata=None):
    return Policy().check(resource, metadata)
