"""Auto-generated from: policies/terraform/azurerm_managed_disk/azurerm_managed_disk_disk_encryption_set.rego
"""
from scanner_core.core.base import BasePolicy, Violation, IssueType, Severity
from scanner_core.core.messages import MANAGED_DISK_ENCRYPTION_REQUIRED


class Policy(BasePolicy):
    name = "azurerm_managed_disk_encryption_set"

    def check(self, resource, metadata=None):
        values = resource.get("values", {})
        des_id = values.get("disk_encryption_set_id", "")
        resource_name = resource.get("name", "unknown")
        
        # Deny if disk_encryption_set_id is NOT set (empty string means not set)
        # Rego condition: des_id != "" means we deny if it's NOT empty
        # This appears to be checking if DES is specified - if NOT, it should fail
        if not des_id:
            return [Violation(
                self.name,
                f"Managed Disk '{resource_name}' did not set disk_encryption_set_id",
                resource,
                issue_type=IssueType.IncorrectValue,
                severity=Severity.MEDIUM,
                code="AZ-SEC-DISK-002"
            )]
        return []


def check(resource, metadata=None):
    return Policy().check(resource, metadata)
