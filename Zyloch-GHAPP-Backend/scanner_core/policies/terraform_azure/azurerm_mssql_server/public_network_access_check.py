"""Auto-generated from: policies/terraform/azurerm_mssql_server/public_network_access_check.rego
"""
from scanner_core.core.base import BasePolicy, Violation, IssueType, Severity
from scanner_core.core.messages import PUBLIC_NETWORK_DISABLED


class Policy(BasePolicy):
    name = "azurerm_mssql_server_public_network_access_check"

    def check(self, resource, metadata=None):
        values = resource.get("values", {})
        public_enabled = values.get("public_network_access_enabled", False)
        
        # Public network access should be disabled (False)
        if public_enabled is True:
            return [Violation(
                self.name,
                PUBLIC_NETWORK_DISABLED,
                resource,
                issue_type=IssueType.Security,
                severity=Severity.HIGH
            )]
        
        return []


def check(resource, metadata=None):
    return Policy().check(resource, metadata)
