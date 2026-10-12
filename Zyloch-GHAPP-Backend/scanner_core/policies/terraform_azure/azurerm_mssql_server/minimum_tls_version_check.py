"""Auto-generated from: policies/terraform/azurerm_mssql_server/minimum_tls_version_check.rego
"""
from scanner_core.core.base import BasePolicy, Violation, IssueType, Severity
from scanner_core.core.messages import MINIMUM_TLS_1_2_REQUIRED


class Policy(BasePolicy):
    name = "azurerm_mssql_server_minimum_tls_version_check"

    def check(self, resource, metadata=None):
        values = resource.get("values", {})
        min_tls = values.get("minimum_tls_version")
        
        # TLS version should be set to "1.2"
        if min_tls != "1.2":
            return [Violation(
                self.name,
                MINIMUM_TLS_1_2_REQUIRED,
                resource,
                issue_type=IssueType.Security,
                severity=Severity.HIGH
            )]
        
        return []


def check(resource, metadata=None):
    return Policy().check(resource, metadata)
