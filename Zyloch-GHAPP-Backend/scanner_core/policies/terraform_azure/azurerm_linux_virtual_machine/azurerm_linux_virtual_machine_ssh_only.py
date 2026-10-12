"""Auto-generated from: policies/terraform/azurerm_linux_virtual_machine/azurerm_linux_virtual_machine_ssh_only.rego
"""
from scanner_core.core.base import BasePolicy, Violation, IssueType, Severity
from scanner_core.core.messages import SSH_PASSWORD_AUTH_ENABLED


class Policy(BasePolicy):
    name = "azurerm_linux_vm_ssh_only"

    def check(self, resource, metadata=None):
        violations = []
        values = resource.get("values", {})
        resource_name = resource.get("name", "unknown")
        
        # Check 1: admin_password should not be set in os_profile
        os_profile = values.get("os_profile") or {}
        admin_password = os_profile.get("admin_password", "")
        if admin_password:
            violations.append(Violation(
                self.name,
                f"Linux VM '{resource_name}' is using basic authentication. Use SSH key authentication instead.",
                resource,
                issue_type=IssueType.Security,
                severity=Severity.HIGH
            ))
        
        # Check 2: disable_password_authentication should be true (default is true)
        os_profile_linux_config = values.get("os_profile_linux_config") or {}
        disable_password_auth = os_profile_linux_config.get("disable_password_authentication", True)
        if disable_password_auth is False:
            violations.append(Violation(
                self.name,
                f"Linux VM '{resource_name}' allows password authentication. Use SSH key authentication only.",
                resource,
                issue_type=IssueType.Security,
                severity=Severity.HIGH
            ))
        
        return violations


def check(resource, metadata=None):
    return Policy().check(resource, metadata)
