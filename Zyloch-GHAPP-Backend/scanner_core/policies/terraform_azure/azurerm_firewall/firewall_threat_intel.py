"""Auto-generated from: policies/terraform/azurerm_firewall/firewall_threat_intel.rego
"""
from scanner_core.core.base import BasePolicy, Violation


class Policy(BasePolicy):
    name = "azurerm_firewall_threat_intel"

    def check(self, resource, metadata=None):
        values = resource.get("values", {})
        # Only applies to firewall resources
        if resource.get("type") != "azurerm_firewall":
            return []
        intel = values.get("threat_intel_mode") or "Off"
        if intel != "Alert":
            from scanner_core.core.messages import FIREWALL_THREAT_INTEL_ALERT_REQUIRED
            return [Violation(self.name, FIREWALL_THREAT_INTEL_ALERT_REQUIRED, resource, params={"name": resource.get('name','')})]
        return []


def check(resource, metadata=None):
    return Policy().check(resource, metadata)
