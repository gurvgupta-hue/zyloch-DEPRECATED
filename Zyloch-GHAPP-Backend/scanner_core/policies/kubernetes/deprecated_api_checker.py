"""
Kubernetes deprecated API version checker.

Auto-imports all ``deprecated_1_xx`` policy modules so they call
``register()`` and populate ``POLICY_REGISTRY``, then exposes
``DeprecatedAPIChecker`` for use by the Kubernetes scanner.

Results are stored as scanner *metadata* (key ``k8s_deprecated``) —
they are NOT added to the regular findings list, so they never appear
on the IaC findings page.  Instead they feed the "Technology Maintenance
Track" section on the overview page.
"""

from __future__ import annotations

import importlib
import pkgutil
from typing import Any, Dict, List, Optional

# ── Auto-register all deprecated_1_xx policy modules ─────────────────────────
import scanner_core.policies.kubernetes as _k8s_pkg  # noqa: E402

for _finder, _modname, _ispkg in pkgutil.iter_modules(_k8s_pkg.__path__):
    if _modname.startswith("deprecated_"):
        try:
            importlib.import_module(f"scanner_core.policies.kubernetes.{_modname}")
        except Exception:
            pass  # Partial registry is acceptable; missing modules are skipped

from scanner_core.policies import POLICY_REGISTRY  # noqa: E402


class DeprecatedAPIChecker:
    """
    Checks Kubernetes resource dicts for deprecated/removed apiVersions.

    Findings describe *which* apiVersion is deprecated, what the
    replacement is, and when it was removed — formatted for the
    Technology Maintenance Track on the overview page.
    """

    def check_resources(
        self, resources: List[Dict[str, Any]], source_file: str
    ) -> List[Dict[str, Any]]:
        """
        Scan a list of Kubernetes resource dicts for deprecated apiVersions.

        Args:
            resources:   Parsed YAML documents from a single manifest file.
            source_file: Relative path of the originating file (used as
                         ``source_file`` in findings for display purposes).

        Returns:
            List of finding dicts, each with the shape::

                {
                  "kind":                str,   # e.g. "Ingress"
                  "deprecated_version":  str,   # e.g. "networking.k8s.io/v1beta1"
                  "replacement_version": str,   # e.g. "networking.k8s.io/v1"
                  "removed_in":          str,   # K8s version, e.g. "1.22"
                  "since":               str,   # deprecation announced, e.g. "1.19"
                  "source_file":         str,
                }
        """
        findings: List[Dict[str, Any]] = []
        for resource in resources:
            if not isinstance(resource, dict):
                continue
            kind = resource.get("kind")
            api_version = resource.get("apiVersion")
            if not kind or not api_version:
                continue
            finding = self._check_resource(kind, api_version, source_file)
            if finding:
                findings.append(finding)
        return findings

    # ── private ──────────────────────────────────────────────────────────────

    def _check_resource(
        self, kind: str, api_version: str, source_file: str
    ) -> Optional[Dict[str, Any]]:
        """
        Return the most relevant deprecation record for *kind* / *api_version*,
        or ``None`` when the combination is not known to be deprecated.

        When the same kind appears in multiple version registries (e.g.
        FlowSchema deprecated in 1.26 AND 1.29), the record with the
        *highest* removal version is returned because that is the most
        actionable migration target.
        """
        def _version_key(v: str) -> tuple:
            # Compare K8s "major.minor" version strings numerically rather
            # than lexicographically - plain string comparison breaks once
            # minor-version widths differ (e.g. "1.9" > "1.22" as strings).
            parts = v.split(".")
            try:
                return tuple(int(p) for p in parts)
            except ValueError:
                return (0,)

        matched: Optional[Dict[str, Any]] = None
        for version, apis in POLICY_REGISTRY.items():
            entry = apis.get(kind)
            if entry and api_version in entry.get("old", []):
                if matched is None or _version_key(version) > _version_key(matched["removed_in"]):
                    matched = {
                        "kind": kind,
                        "deprecated_version": api_version,
                        "replacement_version": entry["new"],
                        "removed_in": version,
                        "since": entry.get("since", version),
                        "source_file": source_file,
                    }
        return matched
