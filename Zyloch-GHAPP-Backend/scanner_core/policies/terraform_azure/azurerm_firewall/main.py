from scanner_core.core.base import BasePolicy, Violation
from .firewall_threat_intel import check as threat_check


class Policy(BasePolicy):
    name = "azurerm_firewall"

    def check(self, resource, metadata=None):
        # aggregate subpolicy checks for firewall
        res = []
        res.extend(threat_check(resource, metadata))
        return res


def check(resource, metadata=None):
    return Policy().check(resource, metadata)
