"""Auto-generated from: policies/terraform/azurerm_synapse_workspace/public_network_access_check.rego
"""
from typing import List
from scanner_core.core.base import BasePolicy, Violation
from scanner_core.core.messages import SYNAPSE_PUBLIC_NETWORK_DISABLED


class Policy(BasePolicy):
    name = "azurerm_synapse_public_network_access_check"

    def check(self, resource, metadata=None) -> List[Violation]:
        values = resource.get("values", {})
        pna = values.get("public_network_access_enabled", True)
        
        if pna == True:
            return [Violation(self.name, SYNAPSE_PUBLIC_NETWORK_DISABLED, resource)]
        
        return []


def check(resource, metadata=None):
    return Policy().check(resource, metadata)
