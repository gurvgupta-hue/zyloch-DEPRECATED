"""Auto-generated from: policies/terraform/azurerm_network_security_group/deny_overly_permissive_tcp.rego
"""
from scanner_core.core.base import BasePolicy, Violation, IssueType, Severity
from scanner_core.core.messages import OVERLY_PERMISSIVE_TCP


class Policy(BasePolicy):
    name = "azurerm_nsg_deny_overly_permissive_tcp"

    def check(self, resource, metadata=None):
        values = resource.get("values", {})
        security_rules = values.get("security_rule") or []
        
        # Check each security rule for overly permissive TCP
        for rule in security_rules:
            if (rule.get("access") == "Allow" and
                rule.get("protocol") == "Tcp" and
                rule.get("destination_port_range") == "*" and
                rule.get("source_address_prefix") == "*"):
                resource_name = resource.get("name", "unknown")
                return [Violation(
                    self.name,
                    f"NSG {resource_name} has overly permissive TCP rule on all ports from Internet",
                    resource,
                    issue_type=IssueType.Security,
                    severity=Severity.HIGH
                )]
        
        return []


def check(resource, metadata=None):
    return Policy().check(resource, metadata)
