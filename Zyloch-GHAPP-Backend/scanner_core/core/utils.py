"""Utility helpers for parsing Terraform plan/state structures."""
import json
from typing import Dict, Any, List, Union


def load_tfplan(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def normalize_resource(resource: Dict[str, Any]) -> Dict[str, Any]:
    """Return a predictable resource dict with keys: type, name, values."""
    return {
        "type": resource.get("type") or resource.get("address") or resource.get("resource_type"),
        "name": resource.get("name") or resource.get("address") or resource.get("resource_name"),
        "values": resource.get("values") or resource.get("attributes") or resource.get("block") or {},
    }


def strip_hcl2_identifier(value: str) -> str:
    """
    Strip surrounding double-quotes that hcl2 v8+ adds to identifier strings
    (resource type labels and resource name labels).

    Example:  '"google_container_cluster"' -> 'google_container_cluster'
    """
    if isinstance(value, str) and len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        return value[1:-1]
    return value


def deduplicate_findings(findings: List) -> List:
    """
    Remove duplicate ScanFinding objects from a list.

    Two findings are considered duplicates only when they share the same
    ``file``, ``code`` and ``description``.  The same violation in two
    different files is a distinct finding and is always kept.  ``description``
    contains the resource name (e.g. ``"[my_bucket] Storage bucket logging
    must be enabled"``), so distinct resources in one file are not merged.
    """
    seen: set = set()
    unique: List = []
    for finding in findings:
        # Works for both ScanFinding Pydantic models and plain dicts
        if hasattr(finding, "code") and hasattr(finding, "description"):
            key = (getattr(finding, "file", None), finding.code, finding.description)
        elif isinstance(finding, dict):
            key = (finding.get("file"), finding.get("code"), finding.get("description"))
        else:
            unique.append(finding)
            continue
        if key not in seen:
            seen.add(key)
            unique.append(finding)
    return unique


def normalize_hcl2_attrs(attrs: Any) -> Any:
    """
    Recursively normalize an hcl2 v8+ parsed attribute dict.

    hcl2 v8 injects a ``__is_block__`` marker key into every nested block body.
    This function strips those markers so policy checkers don't have to deal
    with them.  Block-list structure is intentionally **preserved** (i.e. nested
    blocks that hcl2 returns as a ``[{...}]`` list remain as lists) because many
    checkers iterate over repeated blocks (e.g. ``ingress``, ``egress``).
    Checkers that need to treat a singleton block as a dict should handle the
    list case themselves (several already do: see ``BucketLoggingEnabledChecker``,
    ``StorageBucketVersioningEnabledChecker``, etc.).
    """
    if isinstance(attrs, dict):
        return {k: normalize_hcl2_attrs(v) for k, v in attrs.items() if k != "__is_block__"}
    if isinstance(attrs, list):
        return [normalize_hcl2_attrs(item) for item in attrs]
    return attrs
