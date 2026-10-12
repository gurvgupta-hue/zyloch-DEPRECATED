"""Auto-generated from: policies/terraform/azurerm_mssql_managed_instance/storage_size.rego
"""
from scanner_core.core.base import BasePolicy, Violation, IssueType, Severity
from scanner_core.core.messages import MSSQL_MANAGED_INSTANCE_STORAGE_SIZE_INVALID


class Policy(BasePolicy):
    name = "azurerm_mssql_managed_instance_storage_size"

    def check(self, resource, metadata=None):
        values = resource.get("values", {})
        storage_size = values.get("storage_size_in_gb")
        
        # Check if storage_size_in_gb is set
        if not storage_size:
            return [Violation(
                self.name,
                MSSQL_MANAGED_INSTANCE_STORAGE_SIZE_INVALID,
                resource,
                issue_type=IssueType.MissingValue,
                severity=Severity.MEDIUM
            )]
        
        # Check if storage_size_in_gb is a multiple of 32
        try:
            storage_value = int(storage_size)
        except (ValueError, TypeError):
            return [Violation(
                self.name,
                MSSQL_MANAGED_INSTANCE_STORAGE_SIZE_INVALID,
                resource,
                issue_type=IssueType.IncorrectValue,
                severity=Severity.MEDIUM
            )]
        
        if storage_value % 32 != 0:
            return [Violation(
                self.name,
                MSSQL_MANAGED_INSTANCE_STORAGE_SIZE_INVALID,
                resource,
                issue_type=IssueType.IncorrectValue,
                severity=Severity.MEDIUM
            )]
        
        return []


def check(resource, metadata=None):
    return Policy().check(resource, metadata)
