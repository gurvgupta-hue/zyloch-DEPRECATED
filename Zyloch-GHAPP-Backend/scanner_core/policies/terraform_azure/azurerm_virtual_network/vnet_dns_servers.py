"""Auto-generated from: policies/terraform/azurerm_virtual_network/vnet_dns_servers.rego
"""
from typing import List
from scanner_core.core.base import BasePolicy, Violation
from scanner_core.core.messages import VNET_DNS_SERVERS_REQUIRED


class Policy(BasePolicy):
    name = "azurerm_vnet_dns_servers"

    def check(self, resource, metadata=None) -> List[Violation]:
        values = resource.get("values", {})
        vnet_name = resource.get("name", "")
        dns_servers = values.get("dns_servers", [])
        
        if len(dns_servers) == 0:
            return [Violation(
                self.name,
                VNET_DNS_SERVERS_REQUIRED,
                resource,
                params={"vnet_name": vnet_name}
            )]
        
        return []


def check(resource, metadata=None):
    return Policy().check(resource, metadata)
