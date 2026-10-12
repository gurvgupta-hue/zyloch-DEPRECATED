"""Auto-generated from: policies/terraform/azurerm_managed_disk/main.rego
"""
from scanner_core.core.base import BasePolicy, Violation
from . import azurerm_managed_disk_disk_encryption_set
from . import azurerm_managed_disk_public_network


class Policy(BasePolicy):
    name = "azurerm_managed_disk_main"
    RESOURCE_TYPES = {"azurerm_managed_disk"}

    def check(self, resource, metadata=None):
        if resource.get("type") not in self.RESOURCE_TYPES:
            return []
        violations = []
        violations.extend(azurerm_managed_disk_disk_encryption_set.check(resource, metadata))
        violations.extend(azurerm_managed_disk_public_network.check(resource, metadata))
        return violations


def check(resource, metadata=None):
    return Policy().check(resource, metadata)
