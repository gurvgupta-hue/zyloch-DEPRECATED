"""Auto-generated from: policies/terraform/azurerm_mssql_server/identity_type_check.rego
"""
from scanner_core.core.base import BasePolicy, Violation, IssueType, Severity
from scanner_core.core.messages import IDENTITY_TYPE_INVALID


ALLOWED_IDENTITY_TYPES = {"SystemAssigned", "UserAssigned", "SystemAssigned, UserAssigned"}


class Policy(BasePolicy):
    name = "azurerm_mssql_server_identity_type_check"

    def check(self, resource, metadata=None):
        values = resource.get("values", {})
        identity = values.get("identity")
        
        # Check if identity is set and is a dict with type
        if identity and isinstance(identity, dict):
            identity_type = identity.get("type")
            if identity_type and identity_type not in ALLOWED_IDENTITY_TYPES:
                return [Violation(
                    self.name,
                    IDENTITY_TYPE_INVALID.format(
                        allowed=", ".join(sorted(ALLOWED_IDENTITY_TYPES)),
                        actual=identity_type
                    ),
                    resource,
                    issue_type=IssueType.IncorrectValue,
                    severity=Severity.MEDIUM,
                    code="AZ-SEC-IAM-003"
                )]
        
        return []


def check(resource, metadata=None):
    return Policy().check(resource, metadata)
