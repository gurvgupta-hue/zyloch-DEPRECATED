"""Auto-generated from: policies/terraform/azurerm_storage_blob/type_check.rego
"""
from scanner_core.core.base import BasePolicy, Violation, IssueType, Severity
from scanner_core.core.messages import STORAGE_BLOB_TYPE_INVALID


ALLOWED_TYPES = {"Append", "Block", "Page"}


class Policy(BasePolicy):
    name = "azurerm_storage_blob_type_check"

    def check(self, resource, metadata=None):
        values = resource.get("values", {})
        blob_type = values.get("type", "")
        
        # Check if type is not in allowed values
        if blob_type and blob_type not in ALLOWED_TYPES:
            return [Violation(
                self.name,
                STORAGE_BLOB_TYPE_INVALID.format(allowed=", ".join(sorted(ALLOWED_TYPES))),
                resource,
                issue_type=IssueType.IncorrectValue,
                severity=Severity.MEDIUM,
                code="AZ-SEC-STORAGE-004"
            )]
        
        return []


def check(resource, metadata=None):
    return Policy().check(resource, metadata)
