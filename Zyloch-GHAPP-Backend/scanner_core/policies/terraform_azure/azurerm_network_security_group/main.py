"""Aggregator for NSG checks"""
from typing import List, Optional

from scanner_core.core.base import BasePolicy, Violation
from .deny_inbound_rdp_from_internet import check as rdp_check
from .deny_inbound_ssh_from_internet import check as ssh_check
from .deny_overly_permissive_tcp import check as tcp_check


class Policy(BasePolicy):
    """Aggregator policy for azurerm_network_security_group resource checks."""
    
    name = "azurerm_network_security_group"
    RESOURCE_TYPES = {"azurerm_network_security_group"}

    def check(self, resource: dict, metadata: Optional[dict] = None) -> List[Violation]:
        if resource.get("type") not in self.RESOURCE_TYPES:
            return []
        """Validate network security group resource against all policy rules.
        
        Args:
            resource: Terraform resource dictionary
            metadata: Optional metadata dictionary
            
        Returns:
            List of policy violations found
        """
        violations = []
        for fn in (rdp_check, ssh_check, tcp_check):
            violations.extend(fn(resource, metadata))
        return violations


def check(resource: dict, metadata: Optional[dict] = None) -> List[Violation]:
    return Policy().check(resource, metadata)
