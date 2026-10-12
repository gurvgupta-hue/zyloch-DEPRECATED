"""Auto-generated from: policies/terraform/azurerm_linux_virtual_machine/main.rego
"""
from scanner_core.core.base import BasePolicy, Violation
from . import azurerm_linux_virtual_machine_ssh_only


class Policy(BasePolicy):
    name = "azurerm_linux_vm_main"

    def check(self, resource, metadata=None):
        violations = []
        violations.extend(azurerm_linux_virtual_machine_ssh_only.check(resource, metadata))
        return violations


def check(resource, metadata=None):
    return Policy().check(resource, metadata)
