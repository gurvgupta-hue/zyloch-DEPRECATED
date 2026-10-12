from scanner_core.core.base import BasePolicy, Violation
from scanner_core.core.messages import FTPS_ALLALLOWED


class Policy(BasePolicy):
    name = "common_ftps_state"

    def check(self, resource, metadata=None):
        values = resource.get("values", {})
        ftps_state = values.get("ftps_state") or values.get("ftps")
        # typical allowed values are 'Disabled' or 'AllAllowed' etc.
        if ftps_state and str(ftps_state).lower() == "allallowed":
            return [Violation(self.name, FTPS_ALLALLOWED, resource)]
        return []


def check(resource, metadata=None):
    return Policy().check(resource, metadata)
