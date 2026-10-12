"""Auto-generated from: policies/terraform/azurerm_mssql_database/validate_max_size.rego
"""
from scanner_core.core.base import BasePolicy, Violation, IssueType, Severity
from scanner_core.core.messages import MSSQL_MAX_SIZE_REQUIRED


class Policy(BasePolicy):
    name = "azurerm_mssql_database_validate_max_size"

    def check(self, resource, metadata=None):
        values = resource.get("values", {})
        max_size_gb = values.get("max_size_gb", 0)
        
        try:
            max_size_value = int(max_size_gb) if max_size_gb else 0
        except (ValueError, TypeError):
            max_size_value = 0
        
        if max_size_value <= 0:
            return [Violation(
                self.name,
                MSSQL_MAX_SIZE_REQUIRED,
                resource,
                issue_type=IssueType.IncorrectValue,
                severity=Severity.MEDIUM
            )]
        return []


def check(resource, metadata=None):
    return Policy().check(resource, metadata)
