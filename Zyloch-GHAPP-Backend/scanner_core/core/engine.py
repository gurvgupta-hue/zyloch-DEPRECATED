"""Policy engine: discover and run policy classes/modules.

The engine loads modules under `policy_...python_policies.policies` which
either expose a `Policy` class (subclass of `BasePolicy`) or a
`check(resource, metadata)` function.
"""
from importlib import import_module
import pkgutil
from typing import List, Dict, Callable, Any
from .base import BasePolicy, Violation, IssueType


class PolicyEngine:
    def __init__(self, base_pkg: str = "scanner_core.policies"):
        self.base_pkg = base_pkg
        self._checks: List[Callable[[Dict[str, Any], Dict[str, Any]], List[Violation]]] = []
        self.discover()

    def discover(self):
        try:
            pkg = import_module(self.base_pkg)
        except Exception:
            return

        for finder, name, ispkg in pkgutil.walk_packages(pkg.__path__, pkg.__name__ + "."):
            if ispkg:
                continue
            try:
                mod = import_module(name)
            except Exception:
                continue

            # Prefer class-based Policy
            PolicyCls = getattr(mod, "Policy", None)
            if PolicyCls and issubclass(PolicyCls, BasePolicy):
                inst = PolicyCls()
                self._checks.append(inst.check)
                continue

            # Fallback to a standalone check function
            check_fn = getattr(mod, "check", None)
            if callable(check_fn):
                self._checks.append(check_fn)

    def run(self, resource: Dict, metadata: Dict = None) -> List[Violation]:
        metadata = metadata or {}
        out: List[Violation] = []
        for check in self._checks:
            try:
                # Skip checks that declare RESOURCE_TYPES when the resource type does not match
                resource_types = None
                if hasattr(check, "__self__") and check.__self__:
                    resource_types = getattr(check.__self__, "RESOURCE_TYPES", None)
                if resource_types is None:
                    try:
                        mod = __import__(check.__module__, fromlist=["RESOURCE_TYPES"])
                        resource_types = getattr(mod, "RESOURCE_TYPES", None)
                    except Exception:
                        resource_types = None

                # Heuristic: derive expected resource type from module path (terraform/<resource>/...)
                if not resource_types:
                    try:
                        parts = check.__module__.split(".")
                        if "terraform_azure" in parts:
                            idx = parts.index("terraform")
                            if idx + 1 < len(parts):
                                pkg = parts[idx + 1]
                                pkg_map = {
                                    "azure_keyvault": "azurerm_key_vault",
                                    "azure_servicebus": "azurerm_servicebus_namespace",
                                    "azure_linux_function": "azurerm_linux_function_app",
                                    "azure_windows_function": "azurerm_windows_function_app",
                                    "azure_linux_web_app": "azurerm_linux_web_app",
                                    "azure_windows_web_app": "azurerm_windows_web_app",
                                    "azurerm_storageaccount": "azurerm_storage_account",
                                }
                                expected_type = pkg_map.get(pkg, pkg.replace("azure_", "azurerm_"))
                                if expected_type and resource.get("type") != expected_type:
                                    continue
                    except Exception:
                        pass

                if resource_types and resource.get("type") not in resource_types:
                    continue

                res = check(resource, metadata)
                if res:
                    # normalize and map issue types for returned violations
                    for v in res:
                        # assign mapped issue type based on policy name/message
                        try:
                            pname = getattr(v, "policy", "").lower() if v and getattr(v, "policy", None) else ""
                            msg = getattr(v, "message", "") or ""
                            # mapping rules
                            # First try central definitions
                            try:
                                from scanner_core.core import messages as _messages

                                meta = _messages.VIOLATION_DEFINITIONS.get(getattr(v, "message", ""))
                                if meta:
                                    if hasattr(v, "issue_type"):
                                        v.issue_type = meta.get("issue_type", v.issue_type)
                                    if hasattr(v, "severity"):
                                        v.severity = meta.get("severity", v.severity)
                                    if hasattr(v, "code"):
                                        v.code = meta.get("code", getattr(v, "code", ""))
                                    # mapped and continue
                                    continue
                            except Exception:
                                pass

                            # No central mapping found — leave Violation defaults unchanged
                        except Exception:
                            # if mapping fails, leave the violation as-is
                            pass
                    out.extend(res)
            except Exception as e:
                out.append(
                    Violation(
                        policy=getattr(check, "__name__", "unknown"),
                        message=str(e),
                        resource=resource,
                        issue_type=IssueType.IncorrectValue,
                    )
                )
        return out
