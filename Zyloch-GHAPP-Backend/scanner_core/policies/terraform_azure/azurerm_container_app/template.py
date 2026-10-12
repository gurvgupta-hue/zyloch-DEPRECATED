"""Auto-generated from: policies/terraform/azurerm_container_app/template.rego
"""
from scanner_core.core.base import BasePolicy, Violation, IssueType, Severity
from scanner_core.core.messages import CONTAINER_APP_TEMPLATE


class Policy(BasePolicy):
    name = "azurerm_container_app_template"
    RESOURCE_TYPES = {"azurerm_container_app"}

    def check(self, resource, metadata=None):
        if resource.get("type") not in self.RESOURCE_TYPES:
            return []
        values = resource.get("values", {})
        template = values.get("template", "")
        
        if not template:
            return [Violation(
                self.name,
                CONTAINER_APP_TEMPLATE,
                resource,
                issue_type=IssueType.MissingValue,
                severity=Severity.MEDIUM
            )]
        return []


def check(resource, metadata=None):
    return Policy().check(resource, metadata)
