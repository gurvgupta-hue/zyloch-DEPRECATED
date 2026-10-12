from scanner_core.core.base import BasePolicy, Violation
from scanner_core.core.messages import ALWAYS_ON_REQUIRED


class Policy(BasePolicy):
    name = "common_always_on"

    def check(self, resource, metadata=None):
        values = resource.get("values", {})
        # site_config.always_on or top-level always_on
        site_config = values.get("site_config") or {}
        always_on = site_config.get("always_on") if isinstance(site_config, dict) else None
        if always_on is None:
            always_on = values.get("always_on")
        if always_on is False:
            return [Violation(self.name, ALWAYS_ON_REQUIRED, resource)]
        return []


def check(resource, metadata=None):
    return Policy().check(resource, metadata)
