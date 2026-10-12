"""Auto-generated from: policies/terraform/azurerm_eventgrid_namespace/identity_type_check.rego
"""
from scanner_core.core.base import BasePolicy, Violation, IssueType, Severity
from scanner_core.core.messages import EVENTGRID_IDENTITY_TYPE_INVALID


class Policy(BasePolicy):
    name = "azurerm_eventgrid_identity_type_check"

    def check(self, resource, metadata=None):
        values = resource.get("values", {})
        identity = values.get("identity")
        allowed_types = {"SystemAssigned", "UserAssigned"}
        violations = []
        
        if identity:
            # Handle both single identity dict and list of identity dicts
            identities = identity if isinstance(identity, list) else [identity]
            
            for ident in identities:
                if ident and isinstance(ident, dict):
                    ident_type = ident.get("type")
                    if ident_type and ident_type not in allowed_types:
                        violations.append(Violation(
                            self.name,
                            EVENTGRID_IDENTITY_TYPE_INVALID.format(allowed=allowed_types),
                            resource,
                            issue_type=IssueType.IncorrectValue,
                            severity=Severity.MEDIUM,
                            code="AZ-SEC-EG-003"
                        ))
        
        return violations


def check(resource, metadata=None):
    return Policy().check(resource, metadata)
