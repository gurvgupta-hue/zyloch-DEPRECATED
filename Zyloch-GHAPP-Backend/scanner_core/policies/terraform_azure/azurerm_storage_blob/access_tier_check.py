"""Auto-generated from: policies/terraform/azurerm_storage_blob/access_tier_check.rego
"""
from scanner_core.core.base import BasePolicy, Violation, IssueType, Severity
from scanner_core.core.messages import STORAGE_BLOB_ACCESS_TIER_INVALID


ALLOWED_ACCESS_TIERS = {"Archive", "Cool", "Hot"}


class Policy(BasePolicy):
    name = "azurerm_storage_blob_access_tier_check"

    def check(self, resource, metadata=None):
        values = resource.get("values", {})
        access_tier = values.get("access_tier", "")
        
        # Check if access_tier is set and not in allowed values
        if access_tier and access_tier not in ALLOWED_ACCESS_TIERS:
            return [Violation(
                self.name,
                STORAGE_BLOB_ACCESS_TIER_INVALID.format(allowed=", ".join(sorted(ALLOWED_ACCESS_TIERS))),
                resource,
                issue_type=IssueType.IncorrectValue,
                severity=Severity.MEDIUM,
                code="AZ-SEC-STORAGE-006"
            )]
        
        return []


def check(resource, metadata=None):
    return Policy().check(resource, metadata)
