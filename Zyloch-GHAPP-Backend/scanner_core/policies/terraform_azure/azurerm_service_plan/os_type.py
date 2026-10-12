"""Auto-generated from: policies/terraform/azurerm_service_plan/os_type.rego
"""
from scanner_core.core.base import BasePolicy, Violation, IssueType, Severity
from scanner_core.core.messages import SERVICE_PLAN_OS_UNEXPECTED


ALLOWED_OS_TYPES = {"Windows", "Linux", "WindowsContainer"}


class Policy(BasePolicy):
    name = "azurerm_service_plan_os_type"

    def check(self, resource, metadata=None):
        values = resource.get("values", {})
        os_type = values.get("os_type", "")
        
        # Check if os_type is set and not in allowed values
        if os_type and os_type not in ALLOWED_OS_TYPES:
            return [Violation(
                self.name,
                SERVICE_PLAN_OS_UNEXPECTED.format(os_type=os_type),
                resource,
                issue_type=IssueType.IncorrectValue,
                severity=Severity.MEDIUM
            )]
        return []


def check(resource, metadata=None):
    return Policy().check(resource, metadata)
