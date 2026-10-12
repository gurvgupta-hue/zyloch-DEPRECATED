"""Auto-generated from: policies/terraform/azurerm_application_gateway/http_listener.rego
Original: http_listener.rego
"""
from scanner_core.core.base import BasePolicy, Violation
from scanner_core.core.messages import APP_GW_HTTP_LISTENER_INSECURE


class Policy(BasePolicy):
    name = "azurerm_application_gateway_http_listener"

    def check(self, resource, metadata=None):
        if resource.get("type") != "azurerm_application_gateway":
            return []

        values = resource.get("values", {})
        listeners = values.get("http_listener") or []
        violations = []
        for lst in listeners:
            # listener may be a dict-like object
            protocol = lst.get("protocol") if isinstance(lst, dict) else None
            name = lst.get("name") if isinstance(lst, dict) else None
            if protocol and str(protocol).lower() == "http":
                violations.append(Violation(self.name, APP_GW_HTTP_LISTENER_INSECURE, resource, params={"listener": name}))
        return violations


def check(resource, metadata=None):
    return Policy().check(resource, metadata)
