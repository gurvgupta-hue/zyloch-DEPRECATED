"""Auto-generated from: policies/terraform/azure_windows_function/windows_function_app_runtime.rego
"""
from scanner_core.core.base import BasePolicy, Violation


class Policy(BasePolicy):
    name = "azure_windows_function_app_runtime"

    def check(self, resource, metadata=None):
        # Only evaluate windows function app resources
        if resource.get("type") != "azurerm_windows_function_app":
            return []
        # No runtime-specific checks implemented yet
        return []


def check(resource, metadata=None):
    return Policy().check(resource, metadata)
