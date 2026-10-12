"""Auto-generated from: policies/terraform/azurerm_container_app/revision_mode.rego
"""
from scanner_core.core.base import BasePolicy, Violation, IssueType, Severity
from scanner_core.core.messages import CONTAINER_APP_REVISION_MODE


class Policy(BasePolicy):
    name = "azurerm_container_app_revision_mode"

    def check(self, resource, metadata=None):
        values = resource.get("values", {})
        revision_mode = values.get("revision_mode", "")
        allowed_modes = {"Single", "Multiple"}
        
        if revision_mode and revision_mode not in allowed_modes:
            return [Violation(
                self.name,
                CONTAINER_APP_REVISION_MODE,
                resource,
                issue_type=IssueType.IncorrectValue,
                severity=Severity.MEDIUM
            )]
        return []


def check(resource, metadata=None):
    return Policy().check(resource, metadata)
