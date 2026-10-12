"""Auto-generated from: policies/terraform/azurerm_virtual_network/vnet_private_endpoint.rego
"""
from typing import List
from scanner_core.core.base import BasePolicy, Violation
from scanner_core.core.messages import VNET_PRIVATE_ENDPOINT_POLICIES_REQUIRED


class Policy(BasePolicy):
    name = "azurerm_vnet_private_endpoint"

    def check(self, resource, metadata=None) -> List[Violation]:
        values = resource.get("values", {})
        vnet_name = resource.get("name", "")
        private_endpoint_vnet_policies = values.get("private_endpoint_vnet_policies")
        
        if private_endpoint_vnet_policies == "Disabled":
            return [Violation(
                self.name,
                VNET_PRIVATE_ENDPOINT_POLICIES_REQUIRED,
                resource,
                params={"vnet_name": vnet_name}
            )]
        
        return []


def check(resource, metadata=None):
    return Policy().check(resource, metadata)
