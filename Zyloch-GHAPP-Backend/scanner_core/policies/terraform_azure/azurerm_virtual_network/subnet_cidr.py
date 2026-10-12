"""Auto-generated from: policies/terraform/azurerm_virtual_network/subnet_cidr.rego
"""
from typing import List
from scanner_core.core.base import BasePolicy, Violation
from scanner_core.core.messages import VNET_SUBNET_CIDR_INVALID


class Policy(BasePolicy):
    name = "azurerm_vnet_subnet_cidr"

    def check(self, resource, metadata=None) -> List[Violation]:
        ALLOWED_PREFIX = "10.0."
        violations = []
        
        values = resource.get("values", {})
        subnets = values.get("subnet", [])
        
        for subnet in subnets:
            subnet_name = subnet.get("name", "")
            address_prefixes = subnet.get("address_prefixes", [])
            
            for prefix in address_prefixes:
                if not prefix.startswith(ALLOWED_PREFIX):
                    violations.append(Violation(
                        self.name,
                        VNET_SUBNET_CIDR_INVALID,
                        resource,
                        params={
                            "subnet_name": subnet_name,
                            "cidr": prefix,
                            "required_prefix": ALLOWED_PREFIX
                        }
                    ))
        
        return violations


def check(resource, metadata=None):
    return Policy().check(resource, metadata)
