"""Auto-generated from: policies/terraform/azurerm_storageaccount/account_replication_type_check_allowed.rego
"""
from scanner_core.core.base import BasePolicy, Violation
from scanner_core.core.messages import REPLICATION_NOT_ALLOWED


class Policy(BasePolicy):
    name = "azurerm_storageaccount_replication_type_check"

    def check(self, resource, metadata=None):
        values = resource.get("values", {})
        replication = values.get("account_replication_type") or values.get("replication_type")
        allowed = ("LRS", "GRS", "ZRS", "RAGRS")
        if replication and replication.upper() not in allowed:
            return [Violation(self.name, REPLICATION_NOT_ALLOWED, resource, params={"replication": replication})]
        return []


def check(resource, metadata=None):
    return Policy().check(resource, metadata)
