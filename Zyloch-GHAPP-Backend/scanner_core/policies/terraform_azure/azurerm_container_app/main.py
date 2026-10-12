"""Auto-generated from: policies/terraform/azurerm_container_app/main.rego
"""
from typing import List, Optional

from scanner_core.core.base import BasePolicy, Violation
from . import revision_mode
from . import template


class Policy(BasePolicy):
    """Aggregator policy for azurerm_container_app resource checks."""
    
    name = "azurerm_container_app_main"

    def check(self, resource: dict, metadata: Optional[dict] = None) -> List[Violation]:
        """Validate container app resource against all policy rules.
        
        Args:
            resource: Terraform resource dictionary
            metadata: Optional metadata dictionary
            
        Returns:
            List of policy violations found
        """
        violations = []
        violations.extend(revision_mode.check(resource, metadata))
        violations.extend(template.check(resource, metadata))
        return violations


def check(resource: dict, metadata: Optional[dict] = None) -> List[Violation]:
    return Policy().check(resource, metadata)
