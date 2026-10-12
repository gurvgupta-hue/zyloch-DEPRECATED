from scanner_core.core.base import BasePolicy, Violation
from scanner_core.core.messages import HTTPS_ONLY_REQUIRED


class Policy(BasePolicy):
    name = "common_https_only"

    def check(self, resource, metadata=None):
        values = resource.get("values", {})
        https_only = values.get("https_only") or values.get("enable_https_only") or values.get("https_traffic_only")
        if https_only is False:
            return [Violation(self.name, HTTPS_ONLY_REQUIRED, resource)]
        return []


def check(resource, metadata=None):
    return Policy().check(resource, metadata)
