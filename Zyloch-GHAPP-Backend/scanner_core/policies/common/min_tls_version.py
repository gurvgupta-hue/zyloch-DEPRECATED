from typing import List, Optional

from scanner_core.core.base import BasePolicy, Violation
from scanner_core.core.messages import MIN_TLS_NOT_SET, MIN_TLS_INVALID, MIN_TLS_TOO_WEAK


class Policy(BasePolicy):
    """Policy validator for minimum TLS version configuration."""
    
    name = "common_min_tls_version"
    
    # Resource types that support min_tls_version setting
    SUPPORTED_TYPES = {
        "azurerm_app_service",
        "azurerm_function_app",
        "azurerm_linux_function_app",
        "azurerm_windows_function_app",
        "azurerm_linux_web_app",
        "azurerm_windows_web_app",
        # "azurerm_storage_account",  # Has dedicated policy with different format (TLS1_0, TLS1_1, TLS1_2)
        "azurerm_mysql_server",
        "azurerm_postgresql_server",
        "azurerm_mssql_server",
    }

    def check(self, resource: dict, metadata: Optional[dict] = None) -> List[Violation]:
        """Validate minimum TLS version is set and meets security standards.
        
        Args:
            resource: Terraform resource dictionary
            metadata: Optional metadata dictionary
            
        Returns:
            List of policy violations found
        """
        # Only check resources that support min_tls_version
        resource_type = resource.get("type", "")
        if resource_type not in self.SUPPORTED_TYPES:
            return []
        
        values = resource.get("values", {})
        # Acceptable TLS versions: "1.2", "1.3"
        min_tls = values.get("min_tls_version") or values.get("minimum_tls_version")
        if min_tls is None:
            return [Violation(self.name, MIN_TLS_NOT_SET, resource)]
        try:
            v = float(str(min_tls))
        except Exception:
            return [Violation(self.name, MIN_TLS_INVALID, resource, params={"val": min_tls})]
        if v < 1.2:
            return [Violation(self.name, MIN_TLS_TOO_WEAK, resource, params={"val": min_tls})]
        return []


def check(resource: dict, metadata: Optional[dict] = None) -> List[Violation]:
    """Check function wrapper for policy validation."""
    return Policy().check(resource, metadata)


def check(resource, metadata=None):
    return Policy().check(resource, metadata)
