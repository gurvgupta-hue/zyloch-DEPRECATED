"""Auto-generated from: policies/terraform/azurerm_storageaccount/https_traffic_only_enabled_check.rego
"""
from scanner_core.core.base import BasePolicy, Violation
from scanner_core.core.messages import HTTPS_TRAFFIC_ONLY_REQUIRED


class Policy(BasePolicy):
    name = "azurerm_storageaccount_https_traffic_only_enabled_check"

    def check(self, resource, metadata=None):
        values = resource.get("values", {})
        https_only = values.get("enable_https_traffic_only") or values.get("https_only")
        if https_only is False:
            return [Violation(self.name, HTTPS_TRAFFIC_ONLY_REQUIRED, resource)]
        return []


def check(resource, metadata=None):
    return Policy().check(resource, metadata)
