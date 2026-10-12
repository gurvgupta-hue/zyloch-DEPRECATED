"""Auto-generated from: policies/terraform/azurerm_mssql_managed_instance/identity.rego"""
from scanner_core.core.base import BasePolicy, Violation


class Policy(BasePolicy):
    name = "azurerm_mssql_managed_instance_identity"

    def check(self, resource, metadata=None):
        # Expects terraform resource of type azurerm_mssql_managed_instance
        if resource.get('type') != 'azurerm_mssql_managed_instance':
            return []
        values = resource.get('values', {})
        identity = values.get('identity')
        if identity is None:
            return []
        identity_type = identity.get('type')
        allowed = {"None", "SystemAssigned", "UserAssigned", "SystemAssigned,UserAssigned"}
        if identity_type not in allowed:
            from scanner_core.core.messages import IDENTITY_TYPE_INVALID
            return [Violation(self.name, IDENTITY_TYPE_INVALID, resource, params={"allowed": ",".join(sorted(allowed)), "actual": identity_type})]
        return []


def check(resource, metadata=None):
    return Policy().check(resource, metadata)
