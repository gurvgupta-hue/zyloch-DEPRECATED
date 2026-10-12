"""Auto-generated from: policies/terraform/azurerm_virtual_network/subnet_outbound_access.rego
"""
from typing import List
from scanner_core.core.base import BasePolicy, Violation
from scanner_core.core.messages import VNET_SUBNET_OUTBOUND_ACCESS_ENABLED


class Policy(BasePolicy):
    name = "azurerm_vnet_subnet_outbound_access"

    def check(self, resource, metadata=None) -> List[Violation]:
        violations = []
        
        values = resource.get("values", {})
        subnets = values.get("subnet", [])
        
        for subnet in subnets:
            subnet_name = subnet.get("name", "")
            default_outbound_access_enabled = subnet.get("default_outbound_access_enabled")
            
            if default_outbound_access_enabled == True:
                violations.append(Violation(
                    self.name,
                    VNET_SUBNET_OUTBOUND_ACCESS_ENABLED,
                    resource,
                    params={"subnet_name": subnet_name}
                ))
        
        return violations


def check(resource, metadata=None):
    return Policy().check(resource, metadata)
