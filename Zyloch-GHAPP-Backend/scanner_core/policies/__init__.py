"""
Kubernetes policy registry.

Provides the ``register()`` function imported by the deprecated_1_xx.py
modules and the ``POLICY_REGISTRY`` dict populated by those calls.

Usage (in deprecated_1_xx.py files):
    from scanner_core.policies import register
    register("1.22", DEPRECATED_APIS)
"""

from __future__ import annotations

from typing import Dict

# Maps K8s removal version → {kind: {old: [...], new: "...", since: "..."}}
POLICY_REGISTRY: Dict[str, Dict] = {}


def register(version: str, deprecated_apis: Dict) -> None:
    """Register deprecated API entries for a given Kubernetes removal version.

    Args:
        version: The Kubernetes version in which these APIs were removed
                 (e.g. ``"1.22"``).
        deprecated_apis: Mapping of resource ``kind`` to a dict with keys:
            - ``old``:   list of deprecated apiVersion strings
            - ``new``:   the replacement apiVersion string
            - ``since``: K8s version when the deprecation was first announced
    """
    if version not in POLICY_REGISTRY:
        POLICY_REGISTRY[version] = {}
    POLICY_REGISTRY[version].update(deprecated_apis)
