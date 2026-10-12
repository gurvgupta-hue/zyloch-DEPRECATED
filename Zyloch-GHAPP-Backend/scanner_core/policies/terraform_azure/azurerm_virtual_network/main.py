"""Auto-generated from: policies/terraform/azurerm_virtual_network/main.rego
"""
from typing import List
from scanner_core.core.base import BasePolicy, Violation
from .subnet_cidr import check as subnet_cidr_check
from .subnet_outbound_access import check as subnet_outbound_check
from .vnet_address_space import check as address_space_check
from .vnet_ddos import check as ddos_check
from .vnet_dns_servers import check as dns_check
from .vnet_private_endpoint import check as private_endpoint_check


class Policy(BasePolicy):
    name = "azurerm_vnet_main"
    RESOURCE_TYPES = {"azurerm_virtual_network"}

    def check(self, resource, metadata=None) -> List[Violation]:
        if resource.get("type") not in self.RESOURCE_TYPES:
            return []
        violations = []
        violations.extend(subnet_cidr_check(resource, metadata))
        violations.extend(subnet_outbound_check(resource, metadata))
        violations.extend(address_space_check(resource, metadata))
        violations.extend(ddos_check(resource, metadata))
        violations.extend(dns_check(resource, metadata))
        violations.extend(private_endpoint_check(resource, metadata))
        return violations


def check(resource, metadata=None):
    return Policy().check(resource, metadata)
