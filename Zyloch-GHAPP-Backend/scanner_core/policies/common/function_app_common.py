from typing import List, Optional

from scanner_core.core.base import BasePolicy, Violation
from scanner_core.core.messages import FUNCTION_APP_MISSING_SITE_CONFIG, FUNCTION_RUNTIME_DEPRECATED


class Policy(BasePolicy):
    """Policy validator for function app site_config and runtime configuration."""
    
    name = "common_function_app_common"
    
    FUNCTION_APP_TYPES = {
        "azurerm_linux_function_app",
        "azurerm_windows_function_app",
        "azurerm_function_app",
    }

    def check(self, resource: dict, metadata: Optional[dict] = None) -> List[Violation]:
        """Validate function app site_config and runtime settings.
        
        Args:
            resource: Terraform resource dictionary
            metadata: Optional metadata dictionary
            
        Returns:
            List of policy violations found
        """
        # Only validate function app resources
        resource_type = resource.get("type", "")
        if resource_type not in self.FUNCTION_APP_TYPES:
            return []
        
        values = resource.get("values", {})
        # Example checks: ensure `site_config` exists and runtime is not deprecated
        site_config = values.get("site_config") or {}
        # site_config may be a list (from TF plan), take first element when present
        if isinstance(site_config, list):
            site_cfg = site_config[0] if site_config else {}
        elif isinstance(site_config, dict):
            site_cfg = site_config
        else:
            site_cfg = {}

        runtime = (
            site_cfg.get("linux_fx_version")
            or (site_cfg.get("app_settings") or {}).get("FUNCTIONS_WORKER_RUNTIME")
        )
        if not site_cfg:
            return [Violation(self.name, FUNCTION_APP_MISSING_SITE_CONFIG, resource)]
        if runtime and "deprecated" in str(runtime).lower():
            return [Violation(self.name, FUNCTION_RUNTIME_DEPRECATED, resource)]
        return []


def check(resource: dict, metadata: Optional[dict] = None) -> List[Violation]:
    """Check function wrapper for policy validation."""
    return Policy().check(resource, metadata)
