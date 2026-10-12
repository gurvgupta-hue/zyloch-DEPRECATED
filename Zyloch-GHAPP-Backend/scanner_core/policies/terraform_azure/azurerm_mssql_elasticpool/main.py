"""Auto-generated from: policies/terraform/azurerm_mssql_elasticpool/main.rego
"""
from typing import List, Optional

from scanner_core.core.base import BasePolicy, Violation
from . import sku_name_check
from . import sku_tier_check
from . import per_database_settings_check


class Policy(BasePolicy):
    """Aggregator policy for azurerm_mssql_elasticpool resource checks."""
    
    name = "azurerm_mssql_elasticpool_main"

    def check(self, resource: dict, metadata: Optional[dict] = None) -> List[Violation]:
        """Validate MSSQL elastic pool resource against all policy rules.
        
        Args:
            resource: Terraform resource dictionary
            metadata: Optional metadata dictionary
            
        Returns:
            List of policy violations found
        """
        violations = []
        violations.extend(sku_name_check.check(resource, metadata))
        violations.extend(sku_tier_check.check(resource, metadata))
        violations.extend(per_database_settings_check.check(resource, metadata))
        return violations


def check(resource: dict, metadata: Optional[dict] = None) -> List[Violation]:
    return Policy().check(resource, metadata)
