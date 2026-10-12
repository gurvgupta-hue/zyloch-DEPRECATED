from typing import List, Optional

from scanner_core.core.base import BasePolicy, Violation
from scanner_core.core.messages import OWNER_TAG_MISSING


class Policy(BasePolicy):
    """Policy validator for resource ownership tagging."""
    
    name = "common_owner_tag"
    
    # Resource types that require owner tag
    TAGGABLE_TYPES = {
        "azurerm_app_service",
        "azurerm_function_app",
        "azurerm_linux_function_app",
        "azurerm_windows_function_app",
        "azurerm_linux_web_app",
        "azurerm_windows_web_app",
        "azurerm_storage_account",
        "azurerm_mysql_server",
        "azurerm_postgresql_server",
        "azurerm_mssql_server",
        "azurerm_virtual_machine",
        "azurerm_linux_virtual_machine",
        "azurerm_windows_virtual_machine",
        "azurerm_resource_group",
    }

    def check(self, resource: dict, metadata: Optional[dict] = None) -> List[Violation]:
        """Validate resource has owner tag assigned.
        
        Args:
            resource: Terraform resource dictionary
            metadata: Optional metadata dictionary
            
        Returns:
            List of policy violations found
        """
        # Only check resources that support tagging
        resource_type = resource.get("type", "")
        if resource_type not in self.TAGGABLE_TYPES:
            return []
        
        values = resource.get("values", {})
        tags = values.get("tags") or {}
        if not tags or not tags.get("owner"):
            return [Violation(self.name, OWNER_TAG_MISSING, resource)]
        return []


def check(resource: dict, metadata: Optional[dict] = None) -> List[Violation]:
    """Check function wrapper for policy validation."""
    return Policy().check(resource, metadata)
