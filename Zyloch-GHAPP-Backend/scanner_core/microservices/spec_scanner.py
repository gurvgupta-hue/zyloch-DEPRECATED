"""
Spec Scanner Microservice
Calls the OpenAPI Spec Generator + Validator service (v2/generate-and-validate).
"""

import os
import re
import subprocess
import sys
import time
import uuid
import requests
from typing import Any, Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner_core.base_scanner import (
    BaseScanner,
    ScanRequest,
    ScanResponse,
    ScanResult,
    ScanFinding,
    ScanStatus,
    ScanSeverity,
)
from scanner_core.logging_config import get_scanner_logger

logger = get_scanner_logger()

SPEC_GENERATOR_URL = os.getenv("SPEC_GENERATOR_URL", "http://localhost:8000")
SPEC_GENERATOR_ENDPOINT = os.getenv("SPEC_GENERATOR_ENDPOINT", "/v2/generate-and-validate")
SPEC_GENERATOR_TIMEOUT = int(os.getenv("SPEC_GENERATOR_TIMEOUT", "600"))


# ── Git helpers ──────────────────────────────────────────────────────────────

def _git(repo_path: str, *args: str) -> str:
    """Run a git command in repo_path and return stripped stdout, or ''."""
    try:
        result = subprocess.run(
            ["git", "-C", repo_path, *args],
            capture_output=True, text=True, timeout=10
        )
        return result.stdout.strip()
    except Exception:
        return ""


def _parse_org_repo(remote_url: str):
    """Extract (org, repo) from https or ssh remote URL."""
    remote_url = remote_url.strip().rstrip("/").removesuffix(".git")
    m = re.search(r"[:/]([^/:]+)/([^/]+)$", remote_url)
    if m:
        return m.group(1), m.group(2)
    return "unknown", "unknown"


def _extract_git_metadata(repo_path: str) -> Dict[str, Any]:
    remote_url = _git(repo_path, "remote", "get-url", "origin")
    org, repo = _parse_org_repo(remote_url) if remote_url else ("unknown", "unknown")
    branch = (
        _git(repo_path, "rev-parse", "--abbrev-ref", "HEAD")
        or _git(repo_path, "branch", "--show-current")
        or "main"
    )
    commit_hash = _git(repo_path, "rev-parse", "HEAD") or "unknown"
    commit_message = _git(repo_path, "log", "-1", "--pretty=%s")
    commit_author = _git(repo_path, "log", "-1", "--pretty=%an")
    commit_date = _git(repo_path, "log", "-1", "--pretty=%cI")

    return {
        "organization": org,
        "repository": repo,
        "branch": branch,
        "commit_hash": commit_hash,
        "commit_message": commit_message or None,
        "commit_author": commit_author or None,
        "commit_date": commit_date or None,
        "repository_url": remote_url or None,
    }


# ── Severity / findings helpers ──────────────────────────────────────────────

def _map_severity(value: Any) -> ScanSeverity:
    mapping = {
        "critical": ScanSeverity.CRITICAL,
        "high": ScanSeverity.HIGH,
        "medium": ScanSeverity.MEDIUM,
        "low": ScanSeverity.LOW,
        "info": ScanSeverity.INFO,
    }
    return mapping.get(str(value or "").strip().lower(), ScanSeverity.MEDIUM)


def _api_source_lookup(apis: List[Any]) -> Dict[tuple, Dict[str, Any]]:
    """Index apis by (METHOD, path) for source file/line resolution."""
    lookup: Dict[tuple, Dict[str, Any]] = {}
    for api in apis or []:
        if not isinstance(api, dict):
            continue
        method = api.get("method")
        path = api.get("path")
        if not method or path is None:
            continue
        lookup[(str(method).upper(), path)] = api
    return lookup


def _resolve_source(
    entry: Dict[str, Any], lookup: Dict[tuple, Dict[str, Any]]
) -> tuple:
    """Return (source_file, line_str) from violation fields or apis lookup."""
    method = entry.get("method") or ""
    path = entry.get("path")
    api = lookup.get((str(method).upper(), path)) if path is not None else None
    source_file = entry.get("file") or (api or {}).get("file")
    line = entry.get("line")
    if line is None and api is not None:
        line = api.get("line")
    line_str = str(line) if line is not None and line != "" else None
    return source_file, line_str


def _build_findings(scan_payload: Dict[str, Any]) -> List[ScanFinding]:
    findings: List[ScanFinding] = []
    lookup = _api_source_lookup(scan_payload.get("apis", []) or [])

    for av in scan_payload.get("apiViolations", []) or []:
        if not isinstance(av, dict):
            continue
        method = av.get("method") or ""
        path = av.get("path") or ""
        # file_name in scans_findings stays the endpoint; real path goes on source_file → file.
        endpoint = f"{method} {path}".strip() or "openapi-spec"
        source_file, line_str = _resolve_source(av, lookup)
        findings.append(ScanFinding(
            policy=av.get("violationId") or "OWASP-API",
            severity=_map_severity(av.get("severity")),
            description=av.get("message") or "OWASP API security violation",
            file=endpoint,
            line=line_str,
            source_file=source_file,
            match=av.get("message"),
        ))

    for pv in scan_payload.get("payloadViolations", []) or []:
        if not isinstance(pv, dict):
            continue
        method = pv.get("method") or ""
        path = pv.get("path") or ""
        endpoint = f"{method} {path}".strip() or "openapi-spec"
        source_file, line_str = _resolve_source(pv, lookup)
        findings.append(ScanFinding(
            policy=pv.get("rule") or "PAYLOAD-RULE",
            severity=_map_severity(pv.get("severity")),
            description=pv.get("message") or "Payload validation violation",
            file=endpoint,
            line=line_str,
            source_file=source_file,
            match=pv.get("location"),
        ))

    return findings


def _attach_code_blocks_to_violations(
    scan_payload: Dict[str, Any], findings: List[ScanFinding]
) -> None:
    """
    Copy populated code_block values onto apiViolations / payloadViolations.

    The Spec Scanner UI reads generator_validator.scan.* (not scans_findings),
    so source context must live on those violation objects.
    """
    idx = 0
    for key in ("apiViolations", "payloadViolations"):
        entries = scan_payload.get(key) or []
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if idx >= len(findings):
                return
            if isinstance(entry, dict) and findings[idx].code_block:
                entry["code_block"] = findings[idx].code_block
            idx += 1


# ── Scanner ───────────────────────────────────────────────────────────────────

class SpecScanner(BaseScanner):
    def __init__(self):
        super().__init__("spec-scanner")
        self.base_url = SPEC_GENERATOR_URL.rstrip("/")
        self.endpoint = SPEC_GENERATOR_ENDPOINT
        self.timeout = SPEC_GENERATOR_TIMEOUT

    def scan(self, request: ScanRequest) -> ScanResponse:
        start = time.time()

        git_meta = _extract_git_metadata(request.repo_path)
        logger.info(
            f"[spec-scanner] org={git_meta['organization']} repo={git_meta['repository']} "
            f"branch={git_meta['branch']} commit={git_meta['commit_hash'][:8]}"
        )

        # Spec generator requires scan_id to be a valid UUID
        try:
            scan_uuid = str(uuid.UUID(request.scan_id))
        except (ValueError, TypeError, AttributeError):
            scan_uuid = str(uuid.uuid5(uuid.NAMESPACE_URL, str(request.scan_id)))

        payload = {
            "path": request.repo_path,
            "scan_metadata": {
                "scan_id": scan_uuid,
                "organization": git_meta["organization"],
                "repository": git_meta["repository"],
                "branch": git_meta["branch"],
                "commit_hash": git_meta["commit_hash"],
                "commit_message": git_meta.get("commit_message"),
                "commit_author": git_meta.get("commit_author"),
                "commit_date": git_meta.get("commit_date"),
                "repository_url": git_meta.get("repository_url"),
                "scan_type": "spec-scanner",
            },
        }

        url = f"{self.base_url}{self.endpoint}"
        logger.info(f"[spec-scanner] POST {url} scan_id={request.scan_id}")

        try:
            resp = requests.post(url, json=payload, timeout=self.timeout)
        except requests.RequestException as e:
            logger.error(f"[spec-scanner] HTTP request failed: {e}")
            return self._create_error_response(request.scan_id, f"spec-generator request failed: {e}")

        duration = time.time() - start

        if resp.status_code >= 400:
            err_detail = resp.text[:500]
            # Repos with no discoverable APIs are an empty result, not a scan failure.
            if resp.status_code == 400 and "No API paths could be extracted" in err_detail:
                logger.info(
                    f"[spec-scanner] No APIs discovered for scan_id={request.scan_id}"
                )
                result = ScanResult(
                    scanner_type=self.scanner_type,
                    status=ScanStatus.COMPLETED,
                    findings=[],
                    scanned_files=[],
                    scan_duration=duration,
                    metadata={
                        "no_api_discovered": True,
                        "spec_scan_response": {
                            "detail": "No API paths could be extracted from the repository.",
                            "scan": {"apis": [], "findings": [], "checks": []},
                        },
                    },
                )
                return self._create_success_response(
                    request.scan_id, result, base_path=request.repo_path
                )

            logger.error(f"[spec-scanner] spec-generator returned {resp.status_code}: {err_detail}")
            return self._create_error_response(
                request.scan_id, f"spec-generator HTTP {resp.status_code}: {err_detail}"
            )

        try:
            api_response = resp.json()
        except ValueError as e:
            logger.error(f"[spec-scanner] invalid JSON from spec-generator: {e}")
            return self._create_error_response(request.scan_id, f"invalid JSON from spec-generator: {e}")

        scan_payload = (api_response or {}).get("scan", {}) or {}
        findings = _build_findings(scan_payload)

        scanned_files: List[str] = []
        for api in scan_payload.get("apis", []) or []:
            f = api.get("file") if isinstance(api, dict) else None
            if f and f not in scanned_files:
                scanned_files.append(f)

        result = ScanResult(
            scanner_type=self.scanner_type,
            status=ScanStatus.COMPLETED,
            findings=findings,
            scanned_files=scanned_files,
            scan_duration=duration,
            metadata={"spec_scan_response": api_response},
        )
        response = self._create_success_response(
            request.scan_id, result, base_path=request.repo_path
        )
        # Mutates api_response in place (held on result.metadata) so the UI's
        # generator_validator.scan.apiViolations carry source context.
        _attach_code_blocks_to_violations(scan_payload, findings)
        return response


def scan_spec(request: ScanRequest) -> ScanResponse:
    return SpecScanner().scan(request)
