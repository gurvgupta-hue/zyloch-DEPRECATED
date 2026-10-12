"""Auto-generated from: policies/terraform/azurerm_lb/frontend_ip_configuration.rego
"""
from scanner_core.core.base import BasePolicy, Violation, IssueType, Severity
from scanner_core.core.messages import LB_FRONTEND_IP_CONFIGURATION_REQUIRED


class Policy(BasePolicy):
    name = "azurerm_lb_frontend_ip_configuration"

    def check(self, resource, metadata=None):
        values = resource.get("values", {})
        frontend_ip_config = values.get("frontend_ip_configuration", [])
        
        # Ensure it's a list and has at least one element
        if not frontend_ip_config or (isinstance(frontend_ip_config, list) and len(frontend_ip_config) == 0):
            resource_name = resource.get("name", "unknown")
            return [Violation(
                self.name,
                LB_FRONTEND_IP_CONFIGURATION_REQUIRED.format(name=resource_name),
                resource,
                issue_type=IssueType.MissingValue,
                severity=Severity.MEDIUM,
                code="AZ-SEC-LB-001"
            )]
        return []


def check(resource, metadata=None):
    return Policy().check(resource, metadata)
