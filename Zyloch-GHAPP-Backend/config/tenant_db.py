"""
Multi-tenant (Strategy C) database resolution for the GHAPP scanner service.

Strategy C uses a single MongoDB Atlas cluster with:
  * one control-plane database (``zyloch_control``) that maps external
    identifiers (GitHub installation IDs) to a tenant, and
  * one database **per tenant** (``zyloch_tenant_<tenantId>``) that holds all
    tenant-scoped data, including scan results.

This module reuses the single ``MongoClient`` created by ``config.db`` so that
all tenant databases share one connection pool (no per-tenant sockets).

Control collections consumed here:
  * ``installation_index``  -> { githubInstallationId, tenantId }

Tenant collections consumed here:
  * ``tenant_settings``     -> singleton doc with ``scans`` and ``policies``
  * ``scan_summary``        -> scan index + embedded ``scores``
  * ``scan_results_<scanner>``
"""

import os
import logging
from typing import Optional, Tuple, List, Set

from pymongo.database import Database

from config.db import _db_connection

logger = logging.getLogger(__name__)

CONTROL_DB_NAME = os.getenv("CONTROL_DATABASE_NAME", "zyloch_control")
TENANT_DB_PREFIX = os.getenv("TENANT_DB_PREFIX", "zyloch_tenant_")

SUPPORTED_SCANNERS = (
    "docker", "kubernetes", "workflow", "secret_scanner",
    "terraform_azure", "terraform_gcp", "sbom", "terraform_aws", "spec-scanner",
    "bicep", "ansible",
    # Added with the scanners main introduced after this module was written. They
    # must be listed here or their per-tenant result collections get no indexes.
    "cloudformation", "skill-scanner", "cis-agent",
)

# Maps tenant_settings.scans keys to internal scanner type names.
SCAN_CONFIG_MAP = {
    "workflow": {"workflow"},
    "sbom": {"sbom"},
    "secret-scanner": {"secret_scanner"},
    "ai-vs-human": {"ai-vs-human"},
    "iac": {
        "docker", "kubernetes", "terraform_aws", "terraform_azure",
        "terraform_gcp", "bicep", "ansible", "cloudformation",
    },
    "spec-scanner": {"spec-scanner"},
    # Scanners main added later. Without an entry here a tenant that switches the
    # toggle off still gets the scanner run — filter_scan_types_by_settings only
    # disables what this map names.
    "skill-scanner": {"skill-scanner"},
    "cis-agent": {"cis-agent"},
}

_tenant_indexes_initialized: Set[str] = set()


def _client():
    """Return the shared, connected MongoClient (connecting lazily if needed)."""
    _db_connection.connect()
    return _db_connection._client


def get_control_database() -> Database:
    """Return the control-plane database handle (``zyloch_control``)."""
    return _client()[CONTROL_DB_NAME]


def tenant_db_name(tenant_id: str) -> str:
    """Build the tenant database name from a tenant id (matches Zyloch-Backend)."""
    return f"{TENANT_DB_PREFIX}{tenant_id}"


def get_tenant_db(tenant_id: str) -> Database:
    """Return a tenant database handle for the given tenant id."""
    return _client()[tenant_db_name(tenant_id)]


def resolve_tenant_id(installation_id) -> Optional[str]:
    """Resolve a GitHub installation id to its owning tenant id.

    Args:
        installation_id: GitHub App installation id (int or numeric string).

    Returns:
        The tenant id as a hex string, or ``None`` if no mapping exists.
    """
    if installation_id is None:
        return None
    try:
        gh_id = int(installation_id)
    except (TypeError, ValueError):
        logger.warning(f"Invalid installation_id for tenant resolution: {installation_id!r}")
        return None

    try:
        control = get_control_database()
        doc = control.installation_index.find_one(
            {"githubInstallationId": gh_id}, {"tenantId": 1, "_id": 0}
        )
    except Exception as e:
        logger.error(f"Failed to resolve tenant for installation {gh_id}: {e}", exc_info=True)
        return None

    if not doc or not doc.get("tenantId"):
        logger.warning(f"No tenant mapping found for installation_id={gh_id}")
        return None
    return str(doc["tenantId"])


def get_tenant_db_for_installation(installation_id) -> Tuple[Optional[Database], Optional[str]]:
    """Resolve a GitHub installation id to its tenant database handle.

    Returns:
        A ``(tenant_db, tenant_id)`` tuple. Both are ``None`` when the
        installation cannot be mapped to a tenant.
    """
    tenant_id = resolve_tenant_id(installation_id)
    if not tenant_id:
        return None, None
    return get_tenant_db(tenant_id), tenant_id


def get_tenant_settings(tenant_db: Database) -> dict:
    """Return the singleton ``tenant_settings`` document for a tenant DB.

    Returns an empty dict when no settings document exists yet.
    """
    if tenant_db is None:
        return {}
    try:
        return tenant_db.tenant_settings.find_one({}) or {}
    except Exception as e:
        logger.warning(f"Could not read tenant_settings: {e}")
        return {}


def get_policy_config(tenant_db: Database) -> dict:
    """Return policy config shaped for ``policy_filter`` (``{ scanners: ... }``)."""
    settings = get_tenant_settings(tenant_db)
    policies = settings.get("policies") or {}
    if "scanners" in policies:
        return policies
    return {"scanners": policies.get("scanners", {})}


def filter_scan_types_by_settings(scan_types: List[str], tenant_settings: dict) -> List[str]:
    """Remove scan types disabled in ``tenant_settings.scans``."""
    scan_cfg = tenant_settings.get("scans") or {}
    if not scan_cfg:
        return scan_types
    disabled: Set[str] = set()
    for cfg_key, mapped_types in SCAN_CONFIG_MAP.items():
        if scan_cfg.get(cfg_key) is False:
            disabled.update(mapped_types)
    if not disabled:
        return scan_types
    return [s for s in scan_types if s not in disabled]


def ensure_tenant_scan_indexes(tenant_db: Database, tenant_id: str) -> None:
    """Create scan indexes on a tenant DB (idempotent, once per process per tenant)."""
    if tenant_id in _tenant_indexes_initialized:
        return
    try:
        tenant_db.scan_summary.create_index(
            [("scan_id", 1)], unique=True, name="scan_id_unique"
        )
        tenant_db.scan_summary.create_index(
            [("tenantId", 1), ("scan_id", 1)],
            name="tenant_scan_id_idx",
        )
        tenant_db.scan_summary.create_index(
            [("scan_metadata.tenantId", 1), ("scan_id", 1)],
            name="metadata_tenant_scan_id_idx",
        )
        tenant_db.scan_summary.create_index(
            [
                ("scan_metadata.organization", 1),
                ("scan_metadata.repository", 1),
                ("scan_metadata.branch", 1),
                ("created_at", -1),
            ],
            name="repo_branch_created_idx",
        )
        for scanner in SUPPORTED_SCANNERS:
            collection_name = f"scan_results_{scanner}"
            tenant_db[collection_name].create_index(
                [("tenantId", 1), ("scan_id", 1)],
                name=f"{scanner}_tenant_scan_id_idx",
            )
            tenant_db[collection_name].create_index(
                [
                    ("repo_org", 1),
                    ("repo_name", 1),
                    ("branch", 1),
                    ("created_at", -1),
                ],
                name=f"{scanner}_repo_branch_created_idx",
            )
        _tenant_indexes_initialized.add(tenant_id)
    except Exception as e:
        logger.warning(f"Tenant scan index creation warning for {tenant_id}: {e}")


def resolve_tenant_db_required(installation_id) -> Tuple[Database, str]:
    """Resolve installation to tenant DB or raise ``ValueError``."""
    tenant_db, tenant_id = get_tenant_db_for_installation(installation_id)
    # PyMongo Database objects raise NotImplementedError on bool(), so this
    # must be an explicit `is None` check rather than a truthiness test.
    if tenant_db is None or not tenant_id:
        raise ValueError(f"No tenant mapping for installation_id={installation_id}")
    ensure_tenant_scan_indexes(tenant_db, tenant_id)
    return tenant_db, tenant_id
