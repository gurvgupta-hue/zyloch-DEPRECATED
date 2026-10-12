"""Auto-generated from: policies/terraform/azurerm_synapse_workspace/main.rego
"""
from typing import List
from scanner_core.core.base import BasePolicy, Violation
from .managed_vnet_check import check as managed_vnet_check
from .public_network_access_check import check as public_network_access_check


class Policy(BasePolicy):
    name = "azurerm_synapse_workspace_main"
    RESOURCE_TYPES = {"azurerm_synapse_workspace"}

    def check(self, resource, metadata=None) -> List[Violation]:
        if resource.get("type") not in self.RESOURCE_TYPES:
            return []
        violations = []
        violations.extend(managed_vnet_check(resource, metadata))
        violations.extend(public_network_access_check(resource, metadata))
        return violations


def check(resource, metadata=None):
    return Policy().check(resource, metadata)
