"""Aggregator for azurerm storage account checks"""
from typing import List, Optional

from scanner_core.core.base import BasePolicy, Violation
from .access_tier_check import check as access_tier_check
from .access_tier_check_default import check as access_tier_default_check
from .account_kind_check import check as kind_check
from .account_tier_check import check as tier_check
from .account_replication_type_check_allowed import check as replication_check
from .https_traffic_only_enabled_check import check as https_check
from .min_tls_version_check import check as tls_check


class Policy(BasePolicy):
    """Aggregator policy for azurerm_storage_account resource checks."""
    
    name = "azurerm_storage_account"
    RESOURCE_TYPES = {"azurerm_storage_account"}

    def check(self, resource: dict, metadata: Optional[dict] = None) -> List[Violation]:
        """Validate storage account resource against all policy rules.
        
        Only applies to azurerm_storageaccount resources.
        
        Args:
            resource: Terraform resource dictionary
            metadata: Optional metadata dictionary
            
        Returns:
            List of policy violations found
        """
        if resource.get("type") not in self.RESOURCE_TYPES:
            return []
        violations = []
        for fn in (access_tier_default_check, access_tier_check, kind_check, tier_check, replication_check, https_check, tls_check):
            violations.extend(fn(resource, metadata))
        return violations


def check(resource: dict, metadata: Optional[dict] = None) -> List[Violation]:
    return Policy().check(resource, metadata)
