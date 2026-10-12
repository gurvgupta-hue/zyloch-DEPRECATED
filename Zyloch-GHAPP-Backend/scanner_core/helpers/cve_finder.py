import json
import os
import re
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

import requests
from cvss import CVSS2, CVSS3, CVSS4
from cvss.exceptions import CVSS2Error, CVSS3Error, CVSS4Error
from packaging.version import Version, InvalidVersion
from pymongo import MongoClient
from pymongo.collection import Collection
from pymongo.errors import (
    ConnectionFailure,
    NetworkTimeout,
    PyMongoError,
    ServerSelectionTimeoutError,
)

try:
    from scanner_core.logging_config import get_scanner_logger
    logger = get_scanner_logger()
except ImportError:  # pragma: no cover - fallback for standalone use
    import logging
    logger = logging.getLogger("cve_finder")
    logger.setLevel(logging.INFO)


class CVEMongoConnectionError(Exception):
    """CVE MongoDB is unreachable, unconfigured, or server selection timed out."""


_CONNECTIVITY_ERRORS = (ConnectionFailure, ServerSelectionTimeoutError, NetworkTimeout)

# MongoDB configuration for the CVE database (OSV/NVD/MITRE + KEV + EPSS docs).
CVE_MONGO_URI = os.getenv("cve_repo_url", "")
CVE_DB_NAME = os.getenv("CVE_DATABASE_NAME", "cvedb")
CVE_COLLECTION_NAME = os.getenv("CVE_COLLECTION_NAME", "vulnerabilities")
_DEFAULT_CVE_TIMEOUT_MS = int(os.getenv("CVE_MONGODB_SERVER_SELECTION_TIMEOUT_MS", "10000"))

EPSS_API = "https://api.first.org/data/v1/epss"

# Map our SBOM packageManager values to OSV ecosystem strings.
ECOSYSTEM_MAP: Dict[str, List[str]] = {
    "pypi": ["PyPI", "Python"],
    "npm": ["npm", "Node.js"],
    "maven": ["Maven"],
    "gradle": ["Maven"],  # Gradle uses Maven coordinates in OSV
    "go": ["Go"],
    "ruby": ["RubyGems"],
}

_cve_mongo_client: Optional[MongoClient] = None
_cve_collection: Optional[Collection] = None


def _redact_mongo_uri(uri: str) -> str:
    """Avoid logging credentials from MongoDB URIs."""
    if "@" not in uri or "://" not in uri:
        return uri
    scheme, rest = uri.split("://", 1)
    if "@" not in rest:
        return uri
    hostpart = rest.split("@", 1)[1]
    return f"{scheme}://***:***@{hostpart}"


def get_cve_collection() -> Collection:
    """Return the singleton CVE collection, connecting lazily on first use."""
    global _cve_mongo_client, _cve_collection
    if _cve_collection is not None:
        return _cve_collection

    if not CVE_MONGO_URI:
        logger.error("CVE database not connected: cve_repo_url is not set.")
        raise CVEMongoConnectionError(
            "CVE MongoDB is not configured. Set cve_repo_url."
        )

    safe_uri = _redact_mongo_uri(CVE_MONGO_URI)
    try:
        logger.info(
            "Connecting to CVE MongoDB: %s (db=%s, collection=%s)",
            safe_uri, CVE_DB_NAME, CVE_COLLECTION_NAME,
        )
        client = MongoClient(
            CVE_MONGO_URI,
            serverSelectionTimeoutMS=_DEFAULT_CVE_TIMEOUT_MS,
            connectTimeoutMS=_DEFAULT_CVE_TIMEOUT_MS,
        )
        client.admin.command("ping")
        _cve_mongo_client = client
        _cve_collection = client[CVE_DB_NAME][CVE_COLLECTION_NAME]
        return _cve_collection
    except _CONNECTIVITY_ERRORS as e:
        _cve_mongo_client = None
        _cve_collection = None
        logger.error("CVE database not connected (%s): %s", safe_uri, e)
        raise CVEMongoConnectionError(
            f"Failed to connect to CVE MongoDB ({safe_uri}): {e}"
        ) from e


def close_cve_connection() -> None:
    """Close the CVE MongoDB connection. Useful for cleanup/tests."""
    global _cve_mongo_client, _cve_collection
    if _cve_mongo_client:
        _cve_mongo_client.close()
        _cve_mongo_client = None
        _cve_collection = None


# ---------------------------------------------------------------------------
# CVSS extraction
# ---------------------------------------------------------------------------

def _parse_cvss_v4_vector_score(vector: str) -> Optional[Tuple[float, str]]:
    """Compute a CVSS v4.0 base score/severity from a raw vector string.

    v4.0 has no C/I/A or S (scope) keys and isn't a weighted-sum formula like
    v3.x -- it's resolved via the spec's macrovector/equivalence-class lookup
    table, so this delegates to the maintained `cvss` library rather than
    re-deriving that table by hand.
    """
    if not vector or not vector.startswith("CVSS:4.0"):
        return None
    try:
        parsed = CVSS4(vector)
        return float(parsed.base_score), parsed.severities()[0].upper()
    except (CVSS4Error, IndexError):
        return None


def _parse_cvss_v3_vector_score(vector: str) -> Optional[Tuple[float, str]]:
    """Compute a CVSS v3.1/v3.0 base score/severity from a raw vector string."""
    if not vector or not (vector.startswith("CVSS:3.1") or vector.startswith("CVSS:3.0")):
        return None
    try:
        parsed = CVSS3(vector)
        return float(parsed.base_score), parsed.severities()[0].upper()
    except (CVSS3Error, IndexError):
        return None


def _parse_cvss_v2_vector_score(vector: str) -> Optional[Tuple[float, str]]:
    """Compute a CVSS v2.0 base score/severity from a raw vector string.

    Unlike v3.x/v4.0, CVSS v2 vectors carry no "CVSS:x.y" version prefix
    (e.g. "AV:N/AC:L/Au:N/C:C/I:C/A:C"), so there is no prefix to check here.
    """
    if not vector:
        return None
    try:
        parsed = CVSS2(vector)
        return float(parsed.base_score), parsed.severities()[0].upper()
    except (CVSS2Error, IndexError):
        return None


# Deliberately disabled, not deleted: severity must come from the DB verbatim
# (see _extract_cvss_severity below), never derived from the numeric score.
# Kept here, commented out, in case a caller ever needs the old score->severity
# mapping for reference.
# def _cvss_to_severity(score: float) -> str:
#     if score >= 9.0:
#         return "CRITICAL"
#     if score >= 7.0:
#         return "HIGH"
#     if score >= 4.0:
#         return "MEDIUM"
#     if score > 0:
#         return "LOW"
#     return "NONE"


_NVD_METRIC_KEYS = {"4.0": "cvssMetricV40", "3.1": "cvssMetricV31", "3.0": "cvssMetricV30", "2.0": "cvssMetricV2"}
_MITRE_METRIC_KEYS = {"4.0": "cvssV4_0", "3.1": "cvssV3_1", "3.0": "cvssV3_0", "2.0": "cvssV2_0"}
_NORM_CVSS_SCORE_KEYS = {"4.0": "v4", "3.1": "v3", "3.0": "v3", "2.0": "v2"}


def _extract_cvss_for_versions(
    doc: dict, versions: Tuple[str, ...],
) -> Tuple[Optional[float], Optional[str], Optional[str]]:
    """
    Try to extract a CVSS score/version/vector restricted to *versions* only.

    Severity is deliberately not part of this function's job - it is read
    from the DB verbatim by _extract_cvss_severity() instead. The OSV branch
    below parses a vector via the cvss library, which computes a severity
    label as part of that call, but that half of the result is discarded
    (only the score is kept) so no calculated severity ever escapes here.
    """
    score: Optional[float] = None
    version: Optional[str] = None
    vector: Optional[str] = None

    # --- NVD format ---
    metrics = doc.get("metrics", {})
    for ver in versions:
        entries = metrics.get(_NVD_METRIC_KEYS[ver], [])
        if entries:
            data = entries[0].get("cvssData", {})
            s = data.get("baseScore")
            if s is not None:
                score = float(s)
                version = ver
                vector = data.get("vectorString")
                break

    # --- OSV format ---
    if score is None:
        if "4.0" in versions:
            target_type = "CVSS_V4"
        elif "2.0" in versions:
            target_type = "CVSS_V2"
        else:
            target_type = "CVSS_V3"
        for sev_entry in doc.get("severity", []):
            if sev_entry.get("type") != target_type:
                continue
            vec = sev_entry.get("score", "")
            if target_type == "CVSS_V2":
                # CVSS v2 vectors have no "CVSS:x.y" prefix (e.g. "AV:N/AC:L/...").
                parsed = _parse_cvss_v2_vector_score(vec)
                if parsed is not None:
                    score, _computed_severity = parsed
                    version = "2.0"
                    vector = vec
                    break
                continue
            if not vec.startswith("CVSS:"):
                continue
            vec_version = vec.split("/", 1)[0].replace("CVSS:", "")
            if vec_version not in versions:
                continue
            parser = _parse_cvss_v4_vector_score if vec_version == "4.0" else _parse_cvss_v3_vector_score
            parsed = parser(vec)
            if parsed is not None:
                score, _computed_severity = parsed
                version = vec_version
                vector = vec
                break

    # --- MITRE JSON 5.x format ---
    if score is None:
        containers = doc.get("containers", {})
        adp_list = containers.get("adp", [])
        if not isinstance(adp_list, list):
            adp_list = []
        cna = containers.get("cna", {})
        if not isinstance(cna, dict):
            cna = {}
        for container in [cna] + adp_list:
            for metric in container.get("metrics", []):
                for ver in versions:
                    cvss_data = metric.get(_MITRE_METRIC_KEYS[ver], {})
                    s = cvss_data.get("baseScore")
                    if s is not None:
                        score = float(s)
                        version = ver
                        vector = cvss_data.get("vectorString")
                        break
                if score is not None:
                    break
            if score is not None:
                break

    # --- norm_cvss fallback (sync pipeline's normalised block, DB-sourced) ---
    if score is None:
        norm = doc.get("norm_cvss")
        if isinstance(norm, dict):
            for ver in versions:
                entry = norm.get(_NORM_CVSS_SCORE_KEYS.get(ver, ""))
                if isinstance(entry, dict) and entry.get("score") is not None:
                    score = float(entry["score"])
                    version = ver
                    vector = entry.get("vector")
                    break

    return score, version, vector

_NVD_SEVERITY_METRIC_KEYS = ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2")
_MITRE_SEVERITY_METRIC_KEYS = ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0")
_NORM_CVSS_VERSION_KEYS = ("v4", "v3", "v2")


def _extract_cvss_severity(doc: dict) -> Optional[str]:
    
    # --- NVD format ---
    metrics = doc.get("metrics")
    if isinstance(metrics, dict):
        for key in _NVD_SEVERITY_METRIC_KEYS:
            for entry in metrics.get(key) or []:
                if not isinstance(entry, dict):
                    continue
                cvss_data = entry.get("cvssData")
                label = entry.get("baseSeverity") or (
                    cvss_data.get("baseSeverity") if isinstance(cvss_data, dict) else None
                )
                if label:
                    return str(label)

    # --- MITRE CVE JSON 5.x format ---
    containers = doc.get("containers")
    if isinstance(containers, dict):
        cna = containers.get("cna")
        adp = containers.get("adp")
        candidates = [cna if isinstance(cna, dict) else {}]
        candidates += [c for c in (adp or []) if isinstance(c, dict)]
        for container in candidates:
            for metric in container.get("metrics") or []:
                if not isinstance(metric, dict):
                    continue
                for key in _MITRE_SEVERITY_METRIC_KEYS:
                    data = metric.get(key)
                    if isinstance(data, dict) and data.get("baseSeverity"):
                        return str(data["baseSeverity"])

    # --- OSV / GHSA format ---
    db_specific = doc.get("database_specific")
    if isinstance(db_specific, dict) and db_specific.get("severity"):
        return str(db_specific["severity"])

    # --- fallback: sync pipeline's normalised block ---
    norm = doc.get("norm_cvss")
    if isinstance(norm, dict):
        if norm.get("primary_severity"):
            return str(norm["primary_severity"])
        for key in _NORM_CVSS_VERSION_KEYS:
            entry = norm.get(key)
            if isinstance(entry, dict) and entry.get("severity"):
                return str(entry["severity"])

    return None


def _extract_cvss(doc: dict) -> Tuple[Optional[float], Optional[str], Optional[str], Optional[str]]:
    """
    Extract the CVSS score/version/vector plus the DB-stored severity label from
    an NVD/OSV/MITRE doc.

    score/version/vector: v4.0 is tried first; only when a doc has no v4.0 metric
    at all do we fall back to v3.x (3.1, then 3.0); only when neither v4.0 nor
    v3.x is present do we fall back to v2.0.

    severity: read verbatim from the doc by ``_extract_cvss_severity()`` (source
    field first, ``norm_cvss`` as fallback) -- never derived from the score. A
    doc with no CVSS severity label anywhere yields None even when a score or
    vector is present.
    """
    score, version, vector = _extract_cvss_for_versions(doc, ("4.0",))
    if score is None:
        score, version, vector = _extract_cvss_for_versions(doc, ("3.1", "3.0"))
    if score is None:
        score, version, vector = _extract_cvss_for_versions(doc, ("2.0",))

    severity = _extract_cvss_severity(doc)

    return score, severity, version, vector


def _extract_cwe(doc: dict) -> List[str]:
    """
    Extract CWE IDs (e.g. "CWE-79") from an NVD/OSV/MITRE doc, de-duplicated, order preserved.

    Checks the pre-normalised doc["norm_cwes"] field first, in case a CVE sync
    pipeline has already computed it; falls back to live per-format extraction
    when absent so this stays correct against the current (un-normalised) DB.
    """
    norm = doc.get("norm_cwes")
    if norm:
        return list(dict.fromkeys(str(c) for c in norm))

    cwe_ids: List[str] = []

    def _add(raw: Any) -> None:
        if not raw:
            return
        cwe_id = str(raw).strip().upper()
        if not cwe_id.startswith("CWE-"):
            cwe_id = f"CWE-{cwe_id}"
        if cwe_id != "CWE-" and cwe_id not in cwe_ids:
            cwe_ids.append(cwe_id)

    # --- NVD format ---
    for weakness in doc.get("weaknesses", []):
        for description in weakness.get("description", []):
            value = description.get("value", "")
            if value.startswith("CWE-"):
                _add(value)

    # --- OSV format (GHSA-derived entries carry this under database_specific) ---
    if not cwe_ids:
        db_specific = doc.get("database_specific", {})
        for raw in db_specific.get("cwe_ids", []) or []:
            _add(raw)

    # --- MITRE JSON 5.x format ---
    if not cwe_ids:
        containers = doc.get("containers", {})
        adp_list = containers.get("adp", [])
        if not isinstance(adp_list, list):
            adp_list = []
        cna = containers.get("cna", {})
        if not isinstance(cna, dict):
            cna = {}
        for container in [cna] + adp_list:
            for problem_type in container.get("problemTypes", []):
                for description in problem_type.get("descriptions", []):
                    cwe_id = description.get("cweId")
                    if cwe_id:
                        _add(cwe_id)

    return cwe_ids


def _extract_description(doc: dict) -> str:
    for d in doc.get("descriptions", []):
        if d.get("lang", "").startswith("en"):
            return d.get("value", "")

    if doc.get("details"):
        return doc["details"][:500]

    containers = doc.get("containers", {})
    cna = containers.get("cna", {})
    for d in cna.get("descriptions", []):
        if d.get("lang", "").startswith("en"):
            return d.get("value", "")[:500]

    return ""


def _extract_published(doc: dict) -> Optional[str]:
    return (
        doc.get("published")
        or doc.get("publishedDate")
        or doc.get("published_at")
        or (doc.get("cveMetadata") or {}).get("datePublished")
    )


def _extract_fix_version(affected: List[dict]) -> Optional[str]:
    """Return the earliest fix version recorded across an OSV affected[] list."""
    fixed_versions: List[Any] = []

    for entry in affected:
        for r in entry.get("ranges", []):
            if r.get("type") not in ("SEMVER", "ECOSYSTEM"):
                continue
            for event in r.get("events", []):
                fixed = event.get("fixed")
                if fixed:
                    try:
                        fixed_versions.append(Version(str(fixed).lstrip("v")))
                    except InvalidVersion:
                        fixed_versions.append(str(fixed))

    if not fixed_versions:
        return None

    try:
        parsed = [v for v in fixed_versions if isinstance(v, Version)]
        if parsed:
            return str(min(parsed))
    except Exception:
        pass

    return str(fixed_versions[0])


def _iter_range_segments(events: List[dict]):
    """
    Yield (introduced, fixed, last_affected) Version segments from an OSV
    range's events list.

    OSV ranges routinely carry SEVERAL introduced/fixed pairs - one per
    maintained release line, e.g.
        [introduced 0, fixed 1.2.0, introduced 2.0.0, fixed 2.2.0]
    Each 'introduced' starts a new segment; 'fixed'/'last_affected' close the
    current one. Every segment must be checked independently - collapsing
    them into a single trio both misses vulnerable versions in earlier
    release lines and can mis-clear patched versions in later ones.
    """
    intro: Optional[Version] = None
    fixed: Optional[Version] = None
    last_aff: Optional[Version] = None
    for event in events:
        if "introduced" in event:
            if intro is not None:
                yield (intro, fixed, last_aff)
            raw = event["introduced"]
            try:
                intro = Version("0") if raw in ("0", "") else Version(str(raw).lstrip("v"))
            except InvalidVersion:
                intro = Version("0")
            fixed = last_aff = None
        elif "fixed" in event:
            try:
                fixed = Version(str(event["fixed"]).lstrip("v"))
            except InvalidVersion:
                fixed = None
        elif "last_affected" in event:
            try:
                last_aff = Version(str(event["last_affected"]).lstrip("v"))
            except InvalidVersion:
                last_aff = None
    if intro is not None:
        yield (intro, fixed, last_aff)


def _version_in_range(version: Optional[str], affected: List[dict]) -> bool:
    """
    Check whether *version* falls within any OSV-format affected range.
    Returns True (flag conservatively) when version/ranges are unknown or unparseable.
    """
    if version is None:
        return True

    clean_version = version.lstrip("v").strip()

    try:
        pkg_ver = Version(clean_version)
    except InvalidVersion:
        return True

    has_any_range = False

    for entry in affected:
        for r in entry.get("ranges", []):
            range_type = r.get("type", "")
            if range_type not in ("SEMVER", "ECOSYSTEM"):
                continue

            has_any_range = True

            for introduced, fixed, last_affected in _iter_range_segments(r.get("events", [])):
                try:
                    if introduced is None or pkg_ver < introduced:
                        continue
                    if fixed is not None and pkg_ver >= fixed:
                        continue
                    if last_affected is not None and pkg_ver > last_affected:
                        continue
                    return True
                except Exception:
                    return True

        for ver_entry in entry.get("versions", []):
            try:
                if Version(ver_entry.lstrip("v")) == pkg_ver:
                    return True
            except InvalidVersion:
                if ver_entry.lstrip("v") == clean_version:
                    return True

    if not has_any_range:
        has_versions = any(entry.get("versions") for entry in affected)
        if not has_versions:
            return True

    return False


def _embedded_kev(doc: dict) -> Optional[Tuple[bool, Optional[str], Optional[str]]]:
    
    kev = doc.get("kev")
    if not kev:
        return None
    return bool(kev.get("in_kev")), kev.get("date_added"), kev.get("known_ransomware_campaign")


def _fetch_kev(col: Collection, cve_id: str) -> Tuple[bool, Optional[str], Optional[str]]:
    """Look up CISA KEV enrichment for a single CVE directly from Mongo."""
    if not cve_id.startswith("CVE-"):
        return False, None, None
    try:
        kev_doc = col.find_one({"_id": f"kev:{cve_id}"})
    except PyMongoError as exc:
        logger.warning("KEV lookup failed for %s: %s", cve_id, exc)
        return False, None, None
    if not kev_doc:
        return False, None, None
    return True, kev_doc.get("dateAdded"), kev_doc.get("knownRansomwareCampaignUse")


def _embedded_epss(doc: dict) -> Optional[Tuple[Optional[float], Optional[float], Optional[str]]]:
    
    epss = doc.get("epss")
    if not epss or epss.get("score") is None:
        return None
    score = epss.get("score")
    return score, epss.get("percentile"), epss.get("label") or _epss_label(score)


def _resolve_ghsa(col: Collection, ghsa_id: str) -> Optional[str]:
    
    try:
        doc = col.find_one({"id": ghsa_id}, {"_id": 0, "aliases": 1})
        if doc:
            for alias in doc.get("aliases", []):
                if str(alias).startswith("CVE-"):
                    return str(alias)

        doc = col.find_one({"aliases": ghsa_id}, {"_id": 0, "id": 1})
        if doc:
            found_id = str(doc.get("id", ""))
            if found_id.startswith("CVE-"):
                return found_id
    except PyMongoError as exc:
        logger.warning("GHSA alias resolution failed for %s: %s", ghsa_id, exc)
    return None


def _doc_to_vuln(
    doc: dict,
    col: Collection,
    reachability: str = "UNKNOWN",
    vex_statements: Optional[Dict[str, List[dict]]] = None,
    source_override: Optional[str] = None,
) -> Dict[str, Any]:
    
    main_id = doc.get("id", doc.get("_id", ""))
    cve_id = str(main_id)
    ghsa_id: Optional[str] = cve_id if cve_id.startswith("GHSA-") else None

    for alias in doc.get("aliases", []):
        if str(alias).startswith("CVE-"):
            cve_id = str(alias)
            break

    if ghsa_id and cve_id == ghsa_id:
        resolved = _resolve_ghsa(col, cve_id)
        if resolved:
            cve_id = resolved

    score, severity, cvss_version, cvss_vector = _extract_cvss(doc)
    affected = doc.get("affected", [])

    embedded_kev = _embedded_kev(doc)
    if embedded_kev is not None:
        kev, kev_date_added, kev_ransomware = embedded_kev
    else:
        kev, kev_date_added, kev_ransomware = _fetch_kev(col, cve_id)

    epss_score: Optional[float] = None
    epss_percentile: Optional[float] = None
    epss_label: Optional[str] = None
    embedded_epss = _embedded_epss(doc)
    if embedded_epss is not None:
        epss_score, epss_percentile, epss_label = embedded_epss
    elif cve_id.startswith("CVE-"):
        epss_data = fetch_epss_scores(col, [cve_id]).get(cve_id)
        if epss_data:
            epss_score = epss_data["score"]
            epss_percentile = epss_data["percentile"]
            epss_label = epss_data["label"]

    risk_priority = _risk_priority(score, epss_score, kev, reachability)
    risk_score = _risk_score(score, epss_score, kev, reachability)
    oss_risk = _oss_risk_label(risk_score, kev, reachability)

    vex_status: Optional[str] = None
    vex_justification: Optional[str] = None
    vex_statement_id: Optional[str] = None
    stmts = (vex_statements or {}).get(cve_id)
    if stmts:
        stmt = stmts[-1]  # most recent statement wins
        status = stmt.get("status", "")
        vex_status = VEX_STATUS_LABELS.get(status, status)
        vex_justification = VEX_JUSTIFICATION_SHORT.get(
            stmt.get("justification", ""), stmt.get("justification", "")
        )
        vex_statement_id = stmt.get("statement_id", "")

        if status in ("not_affected", "fixed"):
            if kev:
                logger.warning(
                    "VEX conflict for %s: statement says '%s' but CVE is in "
                    "CISA KEV (confirmed exploited). Keeping IMMEDIATE priority.",
                    cve_id, status,
                )
            else:
                risk_priority = "MONITOR"
        elif status == "affected":
            if risk_priority == "MONITOR" and (score or 0) >= 7.0:
                risk_priority = "HIGH"

    return {
        "cve_id": cve_id,
        "source": source_override or doc.get("source", "osv"),
        "severity": severity,
        "cvss_score": score,
        "cvss_version": cvss_version,
        "cvss_vector": cvss_vector,
        "cwe_ids": _extract_cwe(doc),
        "description": _extract_description(doc)[:300],
        "published": _extract_published(doc),
        "fix_version": _extract_fix_version(affected),
        "kev": kev,
        "kev_date_added": kev_date_added,
        "kev_ransomware": kev_ransomware,
        "epss_score": epss_score,
        "epss_percentile": epss_percentile,
        "epss_label": epss_label,
        "risk_priority": risk_priority,
        "risk_score": risk_score,
        "oss_risk": oss_risk,
        "reachability": reachability,
        "ghsa_id": ghsa_id,
        "vex_status": vex_status,
        "vex_justification": vex_justification,
        "vex_statement_id": vex_statement_id,
    }


def _epss_label(score: float) -> str:
    if score >= 0.90:
        return "CRITICAL"
    if score >= 0.50:
        return "HIGH"
    if score >= 0.10:
        return "MEDIUM"
    if score >= 0.01:
        return "LOW"
    return "MINIMAL"


def _risk_priority(
    cvss: Optional[float],
    epss: Optional[float],
    in_kev: bool,
    reachability: Optional[str] = None,
) -> str:
    
    if in_kev:
        return "IMMEDIATE"

    if reachability == "NOT_REACHABLE":
        return "MONITOR"

    epss_val = epss or 0.0
    cvss_val = cvss or 0.0
    is_reachable = reachability in ("REACHABLE_FUNC", "REACHABLE", "POTENTIALLY_REACHABLE")

    if reachability == "REACHABLE_FUNC" and cvss_val >= 7.0:
        return "IMMEDIATE"
    if is_reachable and cvss_val >= 9.0:
        return "IMMEDIATE"
    if is_reachable and cvss_val >= 7.0:
        return "HIGH"

    if epss_val >= 0.50 and cvss_val >= 7.0:
        return "IMMEDIATE"
    if epss_val >= 0.50 or (epss_val >= 0.10 and cvss_val >= 7.0):
        return "HIGH"
    if epss_val >= 0.01 and cvss_val >= 4.0:
        return "MEDIUM"
    if cvss_val >= 7.0:
        return "MEDIUM"
    if cvss_val >= 4.0:
        return "LOW"
    return "MONITOR"


def _risk_score(
    cvss: Optional[float],
    epss: Optional[float],
    in_kev: bool,
    reachability: Optional[str],
) -> float:
    """Numeric OSS risk score in [0, 1] from CVSS, EPSS/KEV, and reachability."""
    cvss_norm = min(max(cvss or 0.0, 0.0), 10.0) / 10.0
    epss_norm = min(max(epss or 0.0, 0.0), 1.0)
    kev_score = 1.0 if in_kev else 0.0

    reachability_scores = {
        "REACHABLE_FUNC": 1.0,
        "REACHABLE": 0.85,
        "POTENTIALLY_REACHABLE": 0.60,
        "NOT_REACHABLE": 0.0,
        "UNKNOWN": 0.50,
        None: 0.50,
    }
    reach_score = reachability_scores.get(reachability, 0.50)
    exploit_score = max(epss_norm, kev_score)  # KEV (confirmed) dominates EPSS (predicted)

    raw_score = 0.40 * cvss_norm + 0.40 * exploit_score + 0.20 * reach_score

    # Static analysis has false negatives, so halve rather than zero out.
    if reachability == "NOT_REACHABLE" and not in_kev:
        raw_score *= 0.50

    # Confirmed-reachable critical severity is dangerous before EPSS catches up.
    if reachability in ("REACHABLE", "REACHABLE_FUNC") and cvss_norm >= 0.9:
        raw_score = max(raw_score, 0.65)

    # KEV + NOT_REACHABLE lands at MEDIUM rather than maxed out like KEV elsewhere.
    if in_kev:
        raw_score = max(raw_score, 0.50 if reachability == "NOT_REACHABLE" else 0.90)

    return round(min(max(raw_score, 0.0), 1.0), 4)


def _oss_risk_label(
    risk_score: float,
    in_kev: bool = False,
    reachability: Optional[str] = None,
) -> str:
    """oss_risk label: HIGH > MEDIUM > LOW > MONITOR. KEV and confirmed
    reachability each force HIGH ahead of the risk_score thresholds."""
    if in_kev:
        return "HIGH"
    if reachability in ("REACHABLE_FUNC", "REACHABLE"):
        return "HIGH"

    if risk_score >= 0.65:
        return "HIGH"
    if risk_score >= 0.40:
        return "MEDIUM"
    if risk_score >= 0.20:
        return "LOW"
    return "MONITOR"


def fetch_epss_scores(col: Collection, cve_ids: List[str]) -> Dict[str, dict]:
    """
    Fetch EPSS scores for a list of CVE IDs.
    Checks Mongo first (epss:<CVE-ID> docs), falls back to the FIRST.org API
    in batches of 100 for anything missing.
    """
    result: Dict[str, dict] = {}
    if not cve_ids:
        return result

    unique_ids = list(set(cve_ids))

    try:
        epss_ids = [f"epss:{cve_id}" for cve_id in unique_ids]
        for doc in col.find({"_id": {"$in": epss_ids}}):
            cve_id = doc.get("cve_id") or doc["_id"].replace("epss:", "")
            result[cve_id] = {
                "score": doc.get("score"),
                "percentile": doc.get("percentile"),
                "label": doc.get("label") or _epss_label(doc.get("score") or 0),
            }
    except PyMongoError as exc:
        logger.warning("EPSS MongoDB lookup failed: %s", exc)

    missing = [cid for cid in unique_ids if cid not in result]
    if missing:
        logger.info("Fetching EPSS scores for %d CVEs...", len(missing))
        for i in range(0, len(missing), 100):
            batch = missing[i:i + 100]
            try:
                resp = requests.get(EPSS_API, params={"cve": ",".join(batch)}, timeout=30)
                resp.raise_for_status()
                for entry in resp.json().get("data", []):
                    cve_id = entry.get("cve", "")
                    score = float(entry.get("epss", 0))
                    pct = float(entry.get("percentile", 0))
                    result[cve_id] = {
                        "score": round(score, 6),
                        "percentile": round(pct, 6),
                        "label": _epss_label(score),
                    }
                time.sleep(1.0)
            except (requests.RequestException, ValueError) as exc:
                logger.warning("EPSS API batch failed: %s", exc)

    return result


# ---------------------------------------------------------------------------
# Reachability analysis (local filesystem)
# ---------------------------------------------------------------------------
# Unlike the standalone GitHub-based CVE scanner (which fetches source files
# over the GitHub API), the SBOM scanner already has the repository checked
# out locally, so reachability is determined by walking repo_path directly.
#
# Labels:
#   REACHABLE_FUNC         - package imported in production source code AND
#                            the specific vulnerable function (per OSV
#                            affected[].ecosystem_specific/database_specific
#                            affected_functions) is actually called
#   REACHABLE              - package is imported in production source code
#   POTENTIALLY_REACHABLE  - package is imported only in test/spec files
#   NOT_REACHABLE          - package not imported anywhere in the repo
#   UNKNOWN                - no repo_path given, or ecosystem not supported

_SKIP_DIRS = {
    "node_modules", "vendor", ".git", "__pycache__", ".venv", "venv",
    "dist", "build", "target", ".gradle", "coverage",
}
_TEST_DIRS = {
    "test", "tests", "spec", "specs", "fixtures", "mocks",
    "__tests__", "e2e", "integration", "unit",
}

_PYTHON_STDLIB = {
    "abc", "ast", "asyncio", "base64", "binascii", "builtins", "cmath", "codecs",
    "collections", "concurrent", "contextlib", "copy", "csv", "dataclasses",
    "datetime", "decimal", "difflib", "email", "enum", "errno", "fnmatch",
    "fractions", "ftplib", "functools", "gc", "getopt", "getpass", "glob", "gzip",
    "hashlib", "heapq", "hmac", "html", "http", "importlib", "inspect", "io",
    "ipaddress", "itertools", "json", "keyword", "linecache", "locale", "logging",
    "math", "mimetypes", "multiprocessing", "numbers", "operator", "os", "pathlib",
    "pickle", "platform", "pprint", "queue", "random", "re", "shutil", "signal",
    "socket", "socketserver", "sqlite3", "ssl", "stat", "statistics", "string",
    "struct", "subprocess", "sys", "tarfile", "tempfile", "textwrap", "threading",
    "time", "timeit", "token", "tokenize", "traceback", "types", "typing",
    "unicodedata", "unittest", "urllib", "uuid", "warnings", "weakref", "xml",
    "xmlrpc", "zipfile", "zipimport", "zlib", "_thread", "__future__",
    "typing_extensions", "site", "pkg_resources", "setuptools",
}

# Module-name to PyPI package-name aliases (reverse-looked-up below).
_PYPI_ALIASES: Dict[str, str] = {
    "PIL": "Pillow", "pil": "Pillow",
    "cv2": "opencv-python", "sklearn": "scikit-learn",
    "bs4": "beautifulsoup4", "yaml": "PyYAML",
    "dotenv": "python-dotenv", "Crypto": "pycryptodome", "crypto": "pycryptodome",
    "dateutil": "python-dateutil", "jwt": "PyJWT",
    "attr": "attrs", "boto": "boto3",
}


def _pkg_name_to_import_names(pkg_name: str) -> Set[str]:
    """Given a PyPI package name, return the set of module names importing it produces."""
    base = pkg_name.lower().replace("-", "_").replace(".", "_")
    candidates = {base, pkg_name.lower().replace("-", "_")}

    for mod, pkg in _PYPI_ALIASES.items():
        if pkg.lower() == pkg_name.lower():
            candidates.add(mod.lower())

    for prefix in ("python_", "py_", "python-", "py-"):
        if pkg_name.lower().startswith(prefix):
            candidates.add(pkg_name.lower()[len(prefix):].replace("-", "_"))

    
    for suffix in ("-c", "-py", "-python"):
        if pkg_name.lower().endswith(suffix):
            candidates.add(pkg_name.lower()[: -len(suffix)].replace("-", "_"))

    return candidates


def _extract_python_imports_from_source(source: str) -> Set[str]:
    """Extract top-level module names referenced via import/from-import, skipping stdlib."""
    imported: Set[str] = set()

    def _add(dotted: str) -> None:
        top = dotted.split(".")[0].lower()
        if top not in _PYTHON_STDLIB:
            imported.add(top)

    try:
        import ast
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    _add(alias.name)
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    _add(node.module)
    except SyntaxError:
        for m in re.finditer(r"^(?:import|from)\s+([A-Za-z_][A-Za-z0-9_.]*)", source, re.MULTILINE):
            _add(m.group(1))
    return imported


def _match_pypi_import(import_names: Set[str], imports: Set[str]) -> Set[str]:
    """Return the subset of `imports` that is directly one of import_names."""
    return import_names & imports


def _extract_js_requires(source: str) -> Set[str]:
    
    pkgs: Set[str] = set()
    for m in re.finditer(r"""require\s*\(\s*['"]([^'"./][^'"]{0,300})['"]\s*\)""", source):
        pkgs.add(m.group(1).split("/")[0].lower())
    for m in re.finditer(
        r"""import\s+(?:[^'"\n]{0,300}?\s+from\s+)?['"]([^'"./][^'"]{0,300})['"]""",
        source,
    ):
        pkgs.add(m.group(1).split("/")[0].lower())
    return pkgs


def _extract_java_imports(source: str) -> Set[str]:
    """Extract top-level (first two dotted segments) package names from Java import statements."""
    pkgs: Set[str] = set()
    for m in re.finditer(r"^import\s+([\w.]+);", source, re.MULTILINE):
        parts = m.group(1).split(".")
        if len(parts) >= 2:
            pkgs.add(f"{parts[0]}.{parts[1]}".lower())
    return pkgs


def _java_import_matches(group: str, imp: str) -> bool:
    return imp.startswith(group.lower())


def _extract_go_imports(source: str) -> Set[str]:
    """Extract quoted import paths that look like external Go modules (contain a dot)."""
    imps: Set[str] = set()
    for m in re.finditer(r'"([^"]+)"', source):
        imp = m.group(1)
        if "." in imp.split("/")[0]:
            imps.add(imp.lower())
    return imps


def _go_import_matches(pkg: str, imp: str) -> bool:
    return pkg in imp or imp.startswith(pkg)


# ---------------------------------------------------------------------------
# Priority 1: Function-level reachability signatures
# ---------------------------------------------------------------------------
# OSV affected[].ecosystem_specific/database_specific fields sometimes carry
# the name of the vulnerable function/class/method. Extracting these lets us
# upgrade a REACHABLE (package imported) match to REACHABLE_FUNC (the
# specific vulnerable function is actually called) when source evidence
# supports it - the strongest signal short of a live call-path trace.

def _extract_vulnerable_signatures(doc: dict) -> List[dict]:
    """
    Extract vulnerable function signatures from an OSV vulnerability document.

    Returns a list of dicts, each with a compiled regex `pattern` that matches
    the function being called (bare name, dotted module.name, or import).
    Empty list means no function-level data available (caller falls back to
    package-level reachability only).
    """
    sigs: List[dict] = []

    for entry in doc.get("affected", []):
        for field in ("ecosystem_specific", "database_specific"):
            funcs = entry.get(field, {}).get("affected_functions", [])
            if not funcs and field == "ecosystem_specific":
                funcs = entry.get(field, {}).get("functions", [])

            for fn in funcs:
                fn_str = str(fn).strip()
                if not fn_str:
                    continue

                parts = fn_str.split(".")
                func = parts[-1] if parts else fn_str

                pattern = re.compile(
                    r"(?:"
                    + re.escape(func) + r"\s*\("
                    + r"|" + re.escape(fn_str) + r"\s*\("
                    + r"|import\s+" + re.escape(func)
                    + r")",
                    re.IGNORECASE,
                )
                sigs.append({"func": func, "fn_str": fn_str, "pattern": pattern})

        desc = entry.get("details") or doc.get("summary") or doc.get("details") or ""
        for m in re.finditer(r"`([A-Za-z_][A-Za-z0-9_.]*)\(\)`", desc):
            fn_str = m.group(1).strip()
            if fn_str and fn_str not in _PYTHON_STDLIB:
                func = fn_str.split(".")[-1]
                if not any(s["func"] == func for s in sigs):
                    pattern = re.compile(re.escape(func) + r"\s*\(", re.IGNORECASE)
                    sigs.append({"func": func, "fn_str": fn_str, "pattern": pattern})

    return sigs


def _match_function_in_sources(
    sigs: List[dict], source_files: List[Tuple[str, str]],
) -> bool:
    """Return True if any vulnerable function signature matches source content."""
    for _path, source in source_files:
        for sig in sigs:
            if sig["pattern"].search(source):
                return True
    return False


def _reachable_label(
    pkg: str,
    matched_refs: Set[str],
    ref_to_prod_files: Dict[str, List[Tuple[str, str]]],
    prod_files: List[Tuple[str, str]],
    vuln_docs: Optional[Dict[str, dict]],
) -> str:
    """
    A package is REACHABLE once it's imported/required in prod code. When OSV
    data for that package names the specific vulnerable function(s), upgrade
    further to REACHABLE_FUNC if that function is actually called in the
    files that import it.
    """
    if vuln_docs and pkg in vuln_docs:
        sigs = _extract_vulnerable_signatures(vuln_docs[pkg])
        if sigs:
            relevant_files: List[Tuple[str, str]] = []
            for ref in matched_refs:
                relevant_files.extend(ref_to_prod_files.get(ref, []))
            if not relevant_files:
                relevant_files = prod_files
            if _match_function_in_sources(sigs, relevant_files):
                return "REACHABLE_FUNC"
    return "REACHABLE"


def _walk_source_files(
    repo_path: str, extensions: Set[str], max_files: int = 20000,
) -> Tuple[List[Tuple[str, str]], List[Tuple[str, str]]]:
    prod_files: List[Tuple[str, str]] = []
    test_files: List[Tuple[str, str]] = []

    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS and not d.startswith(".")]
        rel_parts = [p.lower() for p in os.path.relpath(root, repo_path).split(os.sep)]
        is_test_dir = any(p in _TEST_DIRS for p in rel_parts)

        for file in files:
            ext = os.path.splitext(file)[1]
            if ext not in extensions:
                continue
            full_path = os.path.join(root, file)
            is_test = (
                is_test_dir
                or file.startswith("test_") or file.endswith("_test" + ext)
                or file.lower().endswith(("_test.py", "_spec.py", ".test.js", ".spec.js", ".test.ts", ".spec.ts"))
            )
            try:
                with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
            except OSError:
                continue

            target = test_files if is_test else prod_files
            if len(target) < max_files:
                target.append((full_path, content))

    return prod_files, test_files


_INFRA_FILE_BASENAMES = {
    "Dockerfile", "dockerfile", "Dockerfile.prod", "Dockerfile.dev",
    "docker-compose.yml", "docker-compose.yaml",
    "docker-compose.prod.yml", "docker-compose.override.yml",
    "Makefile", "makefile",
}


def _scan_infra_file_references(repo_path: str) -> Set[str]:
    
    referenced: Set[str] = set()

    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [
            d for d in dirs
            if d == ".github" or (d not in _SKIP_DIRS and not d.startswith("."))
        ]
        rel_parts = os.path.relpath(root, repo_path).replace("\\", "/").split("/")
        in_workflows = ".github" in rel_parts and "workflows" in rel_parts

        for file in files:
            if not (file in _INFRA_FILE_BASENAMES or (in_workflows and file.endswith((".yml", ".yaml")))):
                continue
            full_path = os.path.join(root, file)
            try:
                with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
            except OSError:
                continue

            for m in re.finditer(r'pip[23]?\s+install\s+([a-zA-Z0-9_\-\[\]>=<.,\s]+)', content):
                for pkg in m.group(1).split():
                    clean = re.sub(r'[>=<\[\]!,].*', '', pkg).strip().lower()
                    if clean and not clean.startswith('-'):
                        referenced.add(clean)
            for m in re.finditer(r'npm\s+(?:install|ci|i)\s+([a-zA-Z0-9_@/\-\s]+)', content):
                for pkg in m.group(1).split():
                    clean = pkg.strip().lower()
                    if clean and not clean.startswith('-'):
                        referenced.add(clean)

    return referenced


def analyze_reachability(
    dependencies: List[Dict[str, Any]],
    repo_path: str,
    vuln_docs: Optional[Dict[str, dict]] = None,
) -> Dict[Tuple[str, str], str]:
    
    pkg_names_by_eco: Dict[str, Set[str]] = {}
    for dep in dependencies:
        name = dep.get("moduleName")
        eco = dep.get("packageManager")
        if not name or not eco:
            continue
        pkg_names_by_eco.setdefault(eco, set()).add(name.lower())

    reach: Dict[Tuple[str, str], str] = {}

    if not repo_path or not os.path.isdir(repo_path):
        return reach

    if "pypi" in pkg_names_by_eco:
        prod_files, test_files = _walk_source_files(repo_path, {".py"})
        prod_imports: Set[str] = set()
        test_imports: Set[str] = set()
        module_to_prod_files: Dict[str, List[Tuple[str, str]]] = {}
        for path, source in prod_files:
            found = _extract_python_imports_from_source(source)
            prod_imports.update(found)
            for mod in found:
                module_to_prod_files.setdefault(mod, []).append((path, source))
        for _, source in test_files:
            test_imports.update(_extract_python_imports_from_source(source))

        # Transitive: a prod file may import a local module (not the vulnerable
        # package itself) that in turn imports it - e.g. app.py imports "utils",
        # and utils.py imports "aiohttp". Scanning app.py alone would miss it.
        local_file_map: Dict[str, str] = {
            os.path.splitext(os.path.basename(path))[0].lower(): source
            for path, source in prod_files
        }
        transitive_imports: Set[str] = set()
        for mod in list(prod_imports):
            local_src = local_file_map.get(mod.split(".")[0])
            if local_src:
                transitive_imports.update(_extract_python_imports_from_source(local_src))

        for pkg in pkg_names_by_eco["pypi"]:
            import_names = _pkg_name_to_import_names(pkg)
            matched_mods = _match_pypi_import(import_names, prod_imports)
            if matched_mods:
                reach[(pkg, "pypi")] = _reachable_label(
                    pkg, matched_mods, module_to_prod_files, prod_files, vuln_docs
                )
            elif _match_pypi_import(import_names, transitive_imports):
                reach[(pkg, "pypi")] = "POTENTIALLY_REACHABLE"
            elif _match_pypi_import(import_names, test_imports):
                reach[(pkg, "pypi")] = "POTENTIALLY_REACHABLE"
            else:
                reach[(pkg, "pypi")] = "NOT_REACHABLE"

    if "npm" in pkg_names_by_eco:
        prod_files, test_files = _walk_source_files(
            repo_path, {".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"}
        )
        prod_requires: Set[str] = set()
        test_requires: Set[str] = set()
        pkg_to_prod_files: Dict[str, List[Tuple[str, str]]] = {}
        for path, source in prod_files:
            found = _extract_js_requires(source)
            prod_requires.update(found)
            for ref in found:
                pkg_to_prod_files.setdefault(ref, []).append((path, source))
        for _, source in test_files:
            test_requires.update(_extract_js_requires(source))

        for pkg in pkg_names_by_eco["npm"]:
            bare = pkg.split("/")[-1] if "/" in pkg else pkg
            matched_refs = {r for r in (pkg, bare) if r in prod_requires}
            if matched_refs:
                reach[(pkg, "npm")] = _reachable_label(
                    pkg, matched_refs, pkg_to_prod_files, prod_files, vuln_docs
                )
            elif pkg in test_requires or bare in test_requires:
                reach[(pkg, "npm")] = "POTENTIALLY_REACHABLE"
            else:
                reach[(pkg, "npm")] = "NOT_REACHABLE"

    for eco in ("maven", "gradle"):
        if eco not in pkg_names_by_eco:
            continue
        prod_files, test_files = _walk_source_files(repo_path, {".java"})
        prod_java: Set[str] = set()
        test_java: Set[str] = set()
        for _, source in prod_files:
            prod_java.update(_extract_java_imports(source))
        for _, source in test_files:
            test_java.update(_extract_java_imports(source))

        for pkg in pkg_names_by_eco[eco]:
            group = pkg.split(":")[0] if ":" in pkg else pkg
            if any(_java_import_matches(group, imp) for imp in prod_java):
                reach[(pkg, eco)] = "REACHABLE"
            elif any(_java_import_matches(group, imp) for imp in test_java):
                reach[(pkg, eco)] = "POTENTIALLY_REACHABLE"
            else:
                reach[(pkg, eco)] = "NOT_REACHABLE"

    if "go" in pkg_names_by_eco:
        prod_files, test_files = _walk_source_files(repo_path, {".go"})
        prod_go: Set[str] = set()
        test_go: Set[str] = set()
        for _, source in prod_files:
            prod_go.update(_extract_go_imports(source))
        for _, source in test_files:
            test_go.update(_extract_go_imports(source))

        for pkg in pkg_names_by_eco["go"]:
            if any(_go_import_matches(pkg, imp) for imp in prod_go):
                reach[(pkg, "go")] = "REACHABLE"
            elif any(_go_import_matches(pkg, imp) for imp in test_go):
                reach[(pkg, "go")] = "POTENTIALLY_REACHABLE"
            else:
                reach[(pkg, "go")] = "NOT_REACHABLE"

    # Packages not found via source imports may still be legitimately used
    # via Dockerfile/docker-compose/Makefile/CI install steps.
    infra_refs = _scan_infra_file_references(repo_path)
    if infra_refs:
        for key, label in list(reach.items()):
            if label != "NOT_REACHABLE":
                continue
            pkg_name = key[0]
            bare = pkg_name.split("/")[-1].replace("-", "_")
            if pkg_name in infra_refs or bare in infra_refs:
                reach[key] = "POTENTIALLY_REACHABLE"

    return reach


# ---------------------------------------------------------------------------
# OpenVEX integration
# ---------------------------------------------------------------------------
# OpenVEX (https://openvex.dev) lets a downstream product state whether a
# vulnerability is actually exploitable in this specific context, overriding
# the generic CVSS/EPSS/KEV-derived risk_priority when applicable.

VEX_STATUS_LABELS = {
    "not_affected":        "VEX:NOT_AFFECTED",
    "fixed":               "VEX:FIXED",
    "under_investigation": "VEX:INVESTIGATING",
    "affected":            "VEX:AFFECTED",
}

VEX_JUSTIFICATION_SHORT = {
    "component_not_present":                             "component absent",
    "vulnerable_code_not_present":                        "vuln code absent",
    "vulnerable_code_not_in_execute_path":                "not in exec path",
    "vulnerable_code_cannot_be_controlled_by_adversary":  "not controllable",
    "inline_mitigations_already_exist":                   "mitigated inline",
}


def load_vex_file(vex_path: str) -> Dict[str, List[dict]]:
    """
    Load an OpenVEX or CycloneDX VEX JSON file into a CVE-ID -> statements map.

    Never raises: returns an empty dict if the file is missing or unparseable
    so a bad/absent VEX file never breaks the rest of the CVE lookup.
    """
    if not vex_path or not os.path.exists(vex_path):
        if vex_path:
            logger.warning("VEX file not found: %s", vex_path)
        return {}

    try:
        with open(vex_path, encoding="utf-8") as fh:
            vex = json.load(fh)
    except (OSError, ValueError) as exc:
        logger.error("Could not load VEX file %s: %s", vex_path, exc)
        return {}

    statements: Dict[str, List[dict]] = {}

    # ---- OpenVEX format ----
    for stmt in vex.get("statements", []):
        vuln = stmt.get("vulnerability", {})
        cve_id = vuln.get("id", "")
        if not cve_id.startswith("CVE-"):
            for alias in vuln.get("aliases", []):
                if str(alias).startswith("CVE-"):
                    cve_id = alias
                    break
        if not cve_id:
            continue

        expiry = stmt.get("expiry_time") or stmt.get("expiry")
        if expiry:
            try:
                exp_dt = datetime.fromisoformat(str(expiry).replace("Z", "+00:00"))
                if exp_dt < datetime.now(timezone.utc):
                    continue  # expired statement - skip
            except (ValueError, TypeError):
                pass

        statements.setdefault(cve_id, []).append({
            "status": stmt.get("status", ""),
            "justification": stmt.get("justification", ""),
            "statement_id": stmt.get("@id") or stmt.get("id", ""),
        })

    # ---- CycloneDX VEX format ----
    for vuln in vex.get("vulnerabilities", []):
        cve_id = vuln.get("id", "")
        if not cve_id.startswith("CVE-"):
            continue
        analysis = vuln.get("analysis", {})
        if not analysis:
            continue
        state_map = {
            "resolved": "fixed", "resolved_with_pedigree": "fixed",
            "exploitable": "affected", "in_triage": "under_investigation",
            "false_positive": "not_affected", "not_affected": "not_affected",
        }
        statements.setdefault(cve_id, []).append({
            "status": state_map.get(analysis.get("state", ""), "under_investigation"),
            "justification": analysis.get("justification", ""),
            "statement_id": vuln.get("bom-ref", ""),
        })

    total = sum(len(v) for v in statements.values())
    logger.info(
        "Loaded VEX file %s: %d statement(s) covering %d CVE(s).",
        vex_path, total, len(statements),
    )
    return statements


def apply_vex_statements(
    results_map: Dict[Tuple[str, str], List[Dict[str, Any]]],
    vex_statements: Dict[str, List[dict]],
) -> None:
    """
    Apply loaded VEX statements to vulnerability dicts in place.

    not_affected/fixed collapse risk_priority to MONITOR, unless the CVE is
    in CISA KEV - a stale or incorrect VEX statement should never silence a
    confirmed actively-exploited vulnerability. affected raises a MONITOR
    priority to HIGH when CVSS is high, since VEX is confirming real
    exploitability here rather than just a generic score.
    """
    if not vex_statements:
        return

    for vulns in results_map.values():
        for v in vulns:
            stmts = vex_statements.get(v["cve_id"])
            if not stmts:
                continue

            stmt = stmts[-1]  # most recent statement wins
            status = stmt.get("status", "")
            v["vex_status"] = VEX_STATUS_LABELS.get(status, status)
            v["vex_justification"] = VEX_JUSTIFICATION_SHORT.get(
                stmt.get("justification", ""), stmt.get("justification", "")
            )
            v["vex_statement_id"] = stmt.get("statement_id", "")

            if status in ("not_affected", "fixed"):
                if v["kev"]:
                    logger.warning(
                        "VEX conflict for %s: statement says '%s' but CVE is in "
                        "CISA KEV (confirmed exploited). Keeping IMMEDIATE priority.",
                        v["cve_id"], status,
                    )
                else:
                    v["risk_priority"] = "MONITOR"
            elif status == "affected":
                if v["risk_priority"] == "MONITOR" and (v["cvss_score"] or 0) >= 7.0:
                    v["risk_priority"] = "HIGH"


# ---------------------------------------------------------------------------
# Bulk lookup entry point
# ---------------------------------------------------------------------------

def _normalize_version(raw: Optional[str]) -> Optional[str]:
    if not raw:
        return None
    v = str(raw).strip()
    if not v or v.lower() == "unspecified":
        return None
    return v


def bulk_find_vulnerabilities(
    dependencies: List[Dict[str, Any]],
    repo_path: Optional[str] = None,
    vex_path: Optional[str] = None,
) -> Dict[Tuple[str, str], List[Dict[str, Any]]]:
    
    try:
        col = get_cve_collection()
    except CVEMongoConnectionError as exc:
        logger.error("CVE lookup disabled - CVE database not connected: %s", exc)
        return {}

    # Build one representative (name, version) per (name_lower, ecosystem) pair,
    # matching the dedup behaviour of the source CVE scanner (first occurrence wins).
    dep_versions: Dict[Tuple[str, str], Optional[str]] = {}
    for dep in dependencies:
        name = dep.get("moduleName")
        eco = dep.get("packageManager")
        if not name or not eco or eco not in ECOSYSTEM_MAP:
            continue
        key = (name.lower(), eco)
        if key not in dep_versions:
            dep_versions[key] = _normalize_version(dep.get("versionInfo"))

    if not dep_versions:
        return {}

    results_map: Dict[Tuple[str, str], List[Dict[str, Any]]] = {key: [] for key in dep_versions}

    resolved_vex_path = vex_path or os.getenv("VEX_FILE")
    vex_statements: Dict[str, List[dict]] = {}
    if resolved_vex_path:
        try:
            vex_statements = load_vex_file(resolved_vex_path)
        except Exception as exc:
            logger.warning("VEX file load failed: %s", exc)

    # Index OSV ecosystem string -> our (name_lower, ecosystem) keys sharing that name,
    # so each returned document can be matched back in O(1) instead of scanning all deps.
    osv_lookup: Dict[Tuple[str, str], List[Tuple[str, str]]] = {}
    all_osv_ecosystems: Set[str] = set()
    all_names = {name for name, _eco in dep_versions}
    for (name_lower, eco) in dep_versions:
        for osv_eco in ECOSYSTEM_MAP.get(eco, []):
            osv_lookup.setdefault((name_lower, osv_eco), []).append((name_lower, eco))
            all_osv_ecosystems.add(osv_eco)

    # ---- Round-trip 1: OSV bulk query ----
    # Fetched eagerly (rather than iterating the cursor once) so the same docs
    # can first seed vuln_docs for function-level reachability (Priority 1)
    # below, then be walked again to build the vulnerability dicts.
    osv_docs: List[dict] = []
    if all_osv_ecosystems and all_names:
        osv_query = {
            "source": "osv",
            "affected": {
                "$elemMatch": {
                    "package.name": {"$in": list(all_names)},
                    "package.ecosystem": {"$in": list(all_osv_ecosystems)},
                }
            },
        }
        try:
            osv_docs = list(col.find(osv_query))
        except PyMongoError as exc:
            logger.warning("OSV bulk query failed: %s", exc)

    # Reachability and VEX statements only depend on dependencies/repo_path/
    # vex_path (plus, for Priority 1 function-level matching, the OSV docs
    # just fetched), not on which CVEs end up matching, so resolve them here -
    # each vulnerability dict can then be built complete, in one pass, below.
    reach_map: Dict[Tuple[str, str], str] = {}
    if repo_path:
        try:
            vuln_docs_by_pkg: Dict[str, dict] = {}
            for doc in osv_docs:
                for affected_entry in doc.get("affected", []):
                    pkg_name = affected_entry.get("package", {}).get("name", "").lower()
                    if pkg_name and pkg_name not in vuln_docs_by_pkg:
                        vuln_docs_by_pkg[pkg_name] = doc
            reach_map = analyze_reachability(dependencies, repo_path, vuln_docs=vuln_docs_by_pkg)
        except Exception as exc:
            logger.warning("Reachability analysis failed: %s", exc)

    if osv_docs:
        osv_hits = 0
        for doc in osv_docs:
            affected = doc.get("affected", [])
            for affected_entry in affected:
                pkg = affected_entry.get("package", {})
                pkg_name = pkg.get("name", "").lower()
                pkg_eco = pkg.get("ecosystem", "")

                matched_keys = osv_lookup.get((pkg_name, pkg_eco))
                if not matched_keys:
                    continue

                for key in matched_keys:
                    version = dep_versions.get(key)
                    if version and not _version_in_range(version, affected):
                        continue

                    vuln = _doc_to_vuln(
                        doc, col,
                        reachability=reach_map.get(key, "UNKNOWN"),
                        vex_statements=vex_statements,
                    )
                    existing_ids = {v["cve_id"] for v in results_map[key]}
                    if vuln["cve_id"] not in existing_ids:
                        results_map[key].append(vuln)
                        osv_hits += 1

        logger.debug("OSV bulk query returned %d vulnerability matches.", osv_hits)

    # ---- Round-trip 2: NVD/MITRE fallback for names with no OSV hits ----
    unmatched_keys = [key for key in dep_versions if not results_map[key] and len(key[0]) >= 4]
    if unmatched_keys:
        fallback_names = sorted({name for name, _eco in unmatched_keys if 5 <= len(name) <= 50})[:50]
        if fallback_names:
            or_clauses = [
                {"descriptions": {"$elemMatch": {
                    "value": {"$regex": rf"\b{re.escape(n)}\b", "$options": "i"}
                }}}
                for n in fallback_names
            ]
            nvd_query = {"source": {"$in": ["nvd", "mitre"]}, "$or": or_clauses}
            try:
                nvd_hits = 0
                for doc in col.find(nvd_query, limit=500):
                    description = _extract_description(doc).lower()
                    cve_id = str(
                        doc.get("id")
                        or (doc.get("cveMetadata") or {}).get("cveId")
                        or doc.get("_id", "")
                    )
                    for key in unmatched_keys:
                        name_lower = key[0]
                        if name_lower not in description:
                            continue
                        existing_ids = {v["cve_id"] for v in results_map[key]}
                        if cve_id in existing_ids:
                            continue
                        vuln = _doc_to_vuln(
                            doc, col,
                            reachability=reach_map.get(key, "UNKNOWN"),
                            vex_statements=vex_statements,
                            source_override=doc.get("source", "nvd"),
                        )
                        results_map[key].append(vuln)
                        nvd_hits += 1
                logger.debug("NVD/MITRE fallback returned %d matches.", nvd_hits)
            except PyMongoError as exc:
                logger.warning("NVD/MITRE fallback query failed: %s", exc)

    # Sort each package's vulnerabilities by risk priority, then CVSS descending
    priority_order = {"IMMEDIATE": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "MONITOR": 4}
    for vulns in results_map.values():
        vulns.sort(key=lambda v: (
            priority_order.get(v["risk_priority"] or "MONITOR", 4),
            -(v["cvss_score"] or 0),
        ))

    return results_map