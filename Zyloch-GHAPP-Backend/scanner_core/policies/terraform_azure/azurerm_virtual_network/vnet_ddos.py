"""Auto-generated from: policies/terraform/azurerm_virtual_network/vnet_ddos.rego
"""
from typing import List
from scanner_core.core.base import BasePolicy, Violation
from scanner_core.core.messages import VNET_DDOS_PROTECTION_REQUIRED


class Policy(BasePolicy):
    name = "azurerm_vnet_ddos"

    def check(self, resource, metadata=None) -> List[Violation]:
        values = resource.get("values", {})
        vnet_name = resource.get("name", "")
        ddos_protection_plan = values.get("ddos_protection_plan", [])
        
        if len(ddos_protection_plan) == 0:
            return [Violation(
                self.name,
                VNET_DDOS_PROTECTION_REQUIRED,
                resource,
                params={"vnet_name": vnet_name}
            )]
        
        return []


def check(resource, metadata=None):
    return Policy().check(resource, metadata)
