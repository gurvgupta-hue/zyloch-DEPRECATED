"""Auto-generated from: policies/terraform/azurerm_synapse_workspace/managed_vnet_check.rego
"""
from typing import List
from scanner_core.core.base import BasePolicy, Violation
from scanner_core.core.messages import SYNAPSE_MANAGED_VNET


class Policy(BasePolicy):
    name = "azurerm_synapse_managed_vnet_check"

    def check(self, resource, metadata=None) -> List[Violation]:
        values = resource.get("values", {})
        managed_vnet = values.get("managed_virtual_network_enabled")
        
        if managed_vnet != True:
            return [Violation(self.name, SYNAPSE_MANAGED_VNET, resource)]
        
        return []


def check(resource, metadata=None):
    return Policy().check(resource, metadata)
