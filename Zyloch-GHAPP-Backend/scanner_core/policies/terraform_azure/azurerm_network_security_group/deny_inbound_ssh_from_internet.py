"""Auto-generated from: policies/terraform/azurerm_network_security_group/deny_inbound_ssh_from_internet.rego
"""
from scanner_core.core.base import BasePolicy, Violation, IssueType, Severity
from scanner_core.core.messages import INBOUND_SSH_ALLOWED


class Policy(BasePolicy):
    name = "azurerm_nsg_deny_inbound_ssh_from_internet"

    def check(self, resource, metadata=None):
        values = resource.get("values", {})
        security_rules = values.get("security_rule") or []
        
        # Check each security rule
        for rule in security_rules:
            if (rule.get("access") == "Allow" and
                rule.get("direction") == "Inbound" and
                rule.get("destination_port_range") == "22" and
                rule.get("source_address_prefix") == "*"):
                resource_name = resource.get("name", "unknown")
                return [Violation(
                    self.name,
                    f"NSG {resource_name} allows inbound SSH (port 22) from Internet",
                    resource,
                    issue_type=IssueType.Security,
                    severity=Severity.CRITICAL
                )]
        
        return []


def check(resource, metadata=None):
    return Policy().check(resource, metadata)
