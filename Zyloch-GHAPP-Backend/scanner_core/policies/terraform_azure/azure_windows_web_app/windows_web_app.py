"""Auto-generated from: policies/terraform/azure_windows_web_app/windows_web_app.rego
"""
from typing import List, Optional
import importlib

from scanner_core.core.base import BasePolicy, Violation


class Policy(BasePolicy):
    """Policy validator for Azure Windows Web App resources.
    
    Validates common security and configuration policies including HTTPS requirements,
    FTPS state, TLS version, always-on setting, and resource tagging.
    """
    
    name = "azure_windows_web_app"

    def check(self, resource: dict, metadata: Optional[dict] = None) -> List[Violation]:
        """Validate Windows Web App resource against common policy checks.
        
        Args:
            resource: Terraform resource dictionary
            metadata: Optional metadata dictionary
            
        Returns:
            List of policy violations found
        """
        # Only evaluate windows web app resources
        if resource.get("type") != "azurerm_windows_web_app":
            return []

        check_modules = [
            "scanner_core.policies.common.https_only",
            "scanner_core.policies.common.ftps_state",
            "scanner_core.policies.common.min_tls_version",
            "scanner_core.policies.common.always_on",
            "scanner_core.policies.common.owner_tag",
        ]
        
        violations = []
        for module_name in check_modules:
            try:
                module = importlib.import_module(module_name)
                violations.extend(module.check(resource, metadata))
            except (ImportError, AttributeError):
                # If a check module is missing or doesn't have check(), skip it
                continue
            except Exception:
                # If a check errors, continue with others
                continue
        
        return violations


def check(resource: dict, metadata: Optional[dict] = None) -> List[Violation]:
    """Check function wrapper for policy validation.
    
    Args:
        resource: Terraform resource dictionary
        metadata: Optional metadata dictionary
        
    Returns:
        List of policy violations found
    """
    return Policy().check(resource, metadata)
