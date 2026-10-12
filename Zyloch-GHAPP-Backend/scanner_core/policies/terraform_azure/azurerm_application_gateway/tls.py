"""Auto-generated from: policies/terraform/azurerm_application_gateway/tls.rego
"""
from scanner_core.core.base import BasePolicy, Violation
from scanner_core.core.messages import APP_GW_TLS_MIN_REQUIRED


class Policy(BasePolicy):
    name = "azurerm_application_gateway_tls"

    def check(self, resource, metadata=None):
        if resource.get("type") != "azurerm_application_gateway":
            return []

        values = resource.get("values", {})
        listeners = values.get("http_listener") or []
        ssl_policies = values.get("ssl_policy") or []
        allowed = {"TLSv1_2", "TLSv1_3"}
        violations = []

        # ssl_policy may be a list; take first policy if present
        for listener in listeners:
            proto = listener.get("protocol") if isinstance(listener, dict) else None
            if not proto or str(proto).lower() != "https":
                continue
            # find corresponding ssl_policy (take first available)
            ssl = ssl_policies[0] if isinstance(ssl_policies, list) and ssl_policies else (ssl_policies if isinstance(ssl_policies, dict) else {})
            tls = ""
            if isinstance(ssl, dict):
                tls = ssl.get("min_protocol_version") or ssl.get("minProtocolVersion") or ""
            # Check all ssl_policy entries; if none enforce allowed TLS, raise violation
            ok = False
            if isinstance(ssl_policies, list):
                for sp in ssl_policies:
                    if isinstance(sp, dict):
                        v = sp.get("min_protocol_version") or sp.get("minProtocolVersion") or ""
                        if v in allowed:
                            ok = True
                            break
            elif isinstance(ssl_policies, dict):
                v = ssl_policies.get("min_protocol_version") or ssl_policies.get("minProtocolVersion") or ""
                if v in allowed:
                    ok = True

            if not ok:
                name = listener.get("name") if isinstance(listener, dict) else None
                violations.append(Violation(self.name, APP_GW_TLS_MIN_REQUIRED, resource, params={"listener": name, "found": tls}))

        return violations


def check(resource, metadata=None):
    return Policy().check(resource, metadata)
