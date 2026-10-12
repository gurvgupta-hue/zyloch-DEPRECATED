"""Auto-generated from: policies/terraform/azurerm_storage_blob/size_check.rego
"""
from scanner_core.core.base import BasePolicy, Violation, IssueType, Severity
from scanner_core.core.messages import STORAGE_BLOB_SIZE_REQUIRED


class Policy(BasePolicy):
    name = "azurerm_storage_blob_size_check"

    def check(self, resource, metadata=None):
        values = resource.get("values", {})
        source_uri = values.get("source_uri", "")
        size = values.get("size")
        
        # size is required if source_uri is not set
        if not source_uri and size is None:
            return [Violation(
                self.name,
                STORAGE_BLOB_SIZE_REQUIRED,
                resource,
                issue_type=IssueType.MissingValue,
                severity=Severity.MEDIUM
            )]
        
        return []


def check(resource, metadata=None):
    return Policy().check(resource, metadata)
