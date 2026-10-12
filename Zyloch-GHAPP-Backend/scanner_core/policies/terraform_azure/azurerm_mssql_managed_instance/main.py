"""Auto-generated from: policies/terraform/azurerm_mssql_managed_instance/main.rego
"""
from scanner_core.core.base import BasePolicy, Violation
from . import license_type
from . import sku_name
from . import storage_size
from . import vcores_set
from . import identity


class Policy(BasePolicy):
    name = "azurerm_mssql_managed_instance_main"

    def check(self, resource, metadata=None):
        violations = []
        violations.extend(license_type.check(resource, metadata))
        violations.extend(sku_name.check(resource, metadata))
        violations.extend(storage_size.check(resource, metadata))
        violations.extend(vcores_set.check(resource, metadata))
        violations.extend(identity.check(resource, metadata))
        return violations


def check(resource, metadata=None):
    return Policy().check(resource, metadata)
