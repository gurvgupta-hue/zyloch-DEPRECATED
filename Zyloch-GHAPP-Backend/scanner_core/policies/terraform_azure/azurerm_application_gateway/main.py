"""Auto-generated from: policies/terraform/azurerm_application_gateway/main.rego
"""
from scanner_core.core.base import BasePolicy, Violation


class Policy(BasePolicy):
    name = "azurerm_application_gateway_main"

    def check(self, resource, metadata=None):
        if resource.get("type") != "azurerm_application_gateway":
            return []

        checks = [
            "scanner_core.policies.terraform.azurerm_application_gateway.http_listener",
            "scanner_core.policies.terraform.azurerm_application_gateway.tls",
        ]
        violations = []
        for mod in checks:
            m = __import__(mod, fromlist=["check"]) 
            try:
                violations.extend(m.check(resource, metadata))
            except Exception:
                continue
        return violations


def check(resource, metadata=None):
    return Policy().check(resource, metadata)
