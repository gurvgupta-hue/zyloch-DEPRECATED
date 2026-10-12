"""Auto-generated from: policies/terraform/azurerm_virtual_network/vnet_address_space.rego
"""
from typing import List
from scanner_core.core.base import BasePolicy, Violation
from scanner_core.core.messages import VNET_ADDRESS_SPACE_INVALID


class Policy(BasePolicy):
    name = "azurerm_vnet_address_space"

    def check(self, resource, metadata=None) -> List[Violation]:
        violations = []
        
        values = resource.get("values", {})
        vnet_name = resource.get("name", "")
        address_spaces = values.get("address_space", [])
        
        for cidr in address_spaces:
            if not cidr.startswith("10."):
                violations.append(Violation(
                    self.name,
                    VNET_ADDRESS_SPACE_INVALID,
                    resource,
                    params={"vnet_name": vnet_name, "cidr": cidr}
                ))
        
        return violations


def check(resource, metadata=None):
    return Policy().check(resource, metadata)
