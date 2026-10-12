"""Auto-generated from: policies/terraform/azurerm_mssql_database/main.rego
"""
from typing import List, Optional

from scanner_core.core.base import BasePolicy, Violation
from . import sku_required
from . import validate_max_size


class Policy(BasePolicy):
    """Aggregator policy for azurerm_mssql_database resource checks."""
    
    name = "azurerm_mssql_database_main"

    def check(self, resource: dict, metadata: Optional[dict] = None) -> List[Violation]:
        """Validate MSSQL database resource against all policy rules.
        
        Args:
            resource: Terraform resource dictionary
            metadata: Optional metadata dictionary
            
        Returns:
            List of policy violations found
        """
        violations = []
        violations.extend(sku_required.check(resource, metadata))
        violations.extend(validate_max_size.check(resource, metadata))
        return violations


def check(resource: dict, metadata: Optional[dict] = None) -> List[Violation]:
    """Check function wrapper for policy validation."""
    return Policy().check(resource, metadata)
