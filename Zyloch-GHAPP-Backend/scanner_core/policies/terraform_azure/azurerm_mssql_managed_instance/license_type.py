"""Auto-generated from: policies/terraform/azurerm_mssql_managed_instance/license_type.rego
"""
from scanner_core.core.base import BasePolicy, Violation, IssueType, Severity
from scanner_core.core.messages import MSSQL_MANAGED_INSTANCE_LICENSE_TYPE_INVALID


class Policy(BasePolicy):
    name = "azurerm_mssql_managed_instance_license_type"

    def check(self, resource, metadata=None):
        values = resource.get("values", {})
        license_type = values.get("license_type")
        allowed_types = {"LicenseIncluded", "BasePrice"}
        
        if license_type and license_type not in allowed_types:
            return [Violation(
                self.name,
                MSSQL_MANAGED_INSTANCE_LICENSE_TYPE_INVALID.format(allowed=", ".join(sorted(allowed_types))),
                resource,
                issue_type=IssueType.IncorrectValue,
                severity=Severity.MEDIUM,
                code="AZ-SEC-SQL-007"
            )]
        return []


def check(resource, metadata=None):
    return Policy().check(resource, metadata)
