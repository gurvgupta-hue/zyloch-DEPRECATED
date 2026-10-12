"""Auto-generated from: policies/terraform/azurerm_service_plan/validate_service_plan.rego.txt
"""
from scanner_core.core.base import BasePolicy, Violation
from . import os_type
from . import sku_name


class Policy(BasePolicy):
    name = "azurerm_service_plan_validate"

    def check(self, resource, metadata=None):
        violations = []
        violations.extend(os_type.check(resource, metadata))
        violations.extend(sku_name.check(resource, metadata))
        return violations


def check(resource, metadata=None):
    return Policy().check(resource, metadata)
