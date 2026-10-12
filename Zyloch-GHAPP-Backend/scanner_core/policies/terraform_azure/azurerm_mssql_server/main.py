"""Auto-generated from: policies/terraform/azurerm_mssql_server/main.rego
"""
from typing import List, Optional

from scanner_core.core.base import BasePolicy, Violation
from . import minimum_tls_version_check
from . import public_network_access_check
from . import identity_type_check


class Policy(BasePolicy):
    """Aggregator policy for azurerm_mssql_server resource checks."""
    
    name = "azurerm_mssql_server_main"

    def check(self, resource: dict, metadata: Optional[dict] = None) -> List[Violation]:
        """Validate MSSQL server resource against all policy rules.
        
        Args:
            resource: Terraform resource dictionary
            metadata: Optional metadata dictionary
            
        Returns:
            List of policy violations found
        """
        violations = []
        violations.extend(minimum_tls_version_check.check(resource, metadata))
        violations.extend(public_network_access_check.check(resource, metadata))
        violations.extend(identity_type_check.check(resource, metadata))
        return violations


def check(resource: dict, metadata: Optional[dict] = None) -> List[Violation]:
    """Check function wrapper for policy validation."""
    return Policy().check(resource, metadata)
