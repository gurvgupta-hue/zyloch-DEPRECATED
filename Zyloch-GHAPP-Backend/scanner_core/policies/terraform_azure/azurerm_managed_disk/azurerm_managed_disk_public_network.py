"""Auto-generated from: policies/terraform/azurerm_managed_disk/azurerm_managed_disk_public_network.rego
"""
from scanner_core.core.base import BasePolicy, Violation, IssueType, Severity
from scanner_core.core.messages import MANAGED_DISK_PUBLIC_NETWORK_DISABLED


class Policy(BasePolicy):
    name = "azurerm_managed_disk_public_network"

    def check(self, resource, metadata=None):
        values = resource.get("values", {})
        # Check if public_network_access_enabled is not true (default is false, which is good)
        # Deny if it's explicitly set to something other than true (which means access is disabled - bad config)
        public_access = values.get("public_network_access_enabled", False)
        resource_name = resource.get("name", "unknown")
        
        # Rego condition: public_access != true means we deny if it's not explicitly true
        # This is checking if the setting is missing or set to false (non-compliant)
        if public_access != True:
            return [Violation(
                self.name,
                f"Managed Disk '{resource_name}' allows public network access ({public_access}). Must be Disabled.",
                resource,
                issue_type=IssueType.Security,
                severity=Severity.HIGH,
                code="AZ-SEC-DISK-001"
            )]
        return []


def check(resource, metadata=None):
    return Policy().check(resource, metadata)
