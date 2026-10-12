"""Helpers for MSSQL elasticpool policies."""
from typing import Any, Dict


def db_settings_valid(entry: Dict[str, Any]) -> bool:
    """Return True if per-database settings entry has valid min_capacity and max_capacity."""
    if not isinstance(entry, dict):
        return False
    minc = entry.get("min_capacity")
    maxc = entry.get("max_capacity")
    try:
        minv = float(minc)
        maxv = float(maxc)
    except Exception:
        return False
    return minv <= maxv
