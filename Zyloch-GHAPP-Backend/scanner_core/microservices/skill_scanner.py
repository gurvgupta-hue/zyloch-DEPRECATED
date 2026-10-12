"""
Skill Security Scanner Microservice

Scans AI-agent skill files for prompt injection, trust-escalation,
OWASP LLM Top 10 violations, and related threat vectors.

Supported file types:
  - Markdown skill files: SKILL.md, CLAUDE.md, AGENTS.md, .cursorrules,
    .github/copilot-instructions.md, .claude/agents/*.md
  - HTML variants of the above (.html / .htm)
  - Plugin manifests: plugin.json
  - MCP manifests: mcp.json, .mcp.json

Layer 1 — deterministic pipeline (v2):
  unicode_detector, tokenizer, html_detector, owasp_detector, fragmented,
  self_replication_detector, harness_impersonation_detector,
  agentic_detector, exfiltration_detector, skill_frontmatter_detector,
  config_target_detector, plugin_manifest_detector, mcp_manifest_detector,
  payload_decoder  →  allowlist  →  frameworks.enrich (crosswalk)

Layer 2 — optional LLM pass (set enable_llm=True in ScanRequest.metadata).

Framework crosswalk (back-filled by frameworks.enrich after all detectors):
  asi_id    — OWASP Agentic AI Top 10 (ASI01–ASI10)
  nist_rmf  — NIST AI RMF 1.0 + GenAI Profile (AI 600-1)
  atlas_ids — MITRE ATLAS v5.6.0 techniques & mitigations

Zyloch ScanFinding field mapping:
  policy      — "<detector>:<type>"   (Layer 1) | "llm:<type>" (Layer 2)
  severity    — ScanSeverity enum
  description — human-readable text with embedded framework IDs
  code        — OWASP LLM Top 10 ID (e.g. "LLM01")
  match       — matched snippet / decoded payload (capped at 500 chars)
  file        — repo-relative path of the scanned file
  line        — line number as string
  deny        — MITRE ATLAS technique/mitigation IDs (e.g. ["AML.T0068"])
  url         — NIST AI RMF controls joined as a readable string
                (e.g. "MEASURE 2.7 | MS-2.7-007")
  column      — OWASP Agentic Top 10 ID (e.g. "ASI01")
"""
from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional
from scanner_core.base_scanner import (
    BaseScanner,
    ScanFinding,
    ScanRequest,
    ScanResponse,
    ScanResult,
    ScanSeverity,
    ScanStatus,
)
from scanner_core.helpers.scoring_engine import OPABasedScoreAdapter
from scanner_core.logging_config import get_scanner_logger

logger = get_scanner_logger()


from scanner_core.detectors import (
    agentic_detector,
    bundle_detector,
    config_target_detector,
    exfiltration_detector,
    fragmented,
    harness_impersonation_detector,
    html_detector,
    mcp_manifest_detector,
    owasp_detector,
    payload_decoder,
    plugin_manifest_detector,
    self_replication_detector,
    skill_frontmatter_detector,
    tokenizer,
    unicode_detector,
)
from scanner_core.helpers import allowlist, frameworks
from scanner_core.helpers.models import Layer1Finding, Layer2Finding

_DETECTORS_AVAILABLE = True


# Severity mapping
_SEVERITY_MAP: Dict[str, ScanSeverity] = {
    "CRITICAL": ScanSeverity.CRITICAL,
    "HIGH":     ScanSeverity.HIGH,
    "MEDIUM":   ScanSeverity.MEDIUM,
    "LOW":      ScanSeverity.LOW,
    "INFO":     ScanSeverity.INFO,
}

# ---------------------------------------------------------------------------
# File-discovery constants
#
# Rule mirrors the v2 app's own acceptance logic (main.py ALLOWED_SUFFIXES):
# any .md / .html / .htm file is a candidate skill file; plugin.json, mcp.json
# and .mcp.json are manifest files.  The detectors decide what is interesting.
# ---------------------------------------------------------------------------
_SKILL_EXTENSIONS = {".md", ".html", ".htm"}
_MANIFEST_NAMES   = {"plugin.json", "mcp.json", ".mcp.json"}

# Directories pruned during os.walk — never contain skill files.
_SKIP_DIRS = {
    ".git", "__pycache__", "node_modules", ".venv", "venv",
    "site-packages", ".mypy_cache", ".pytest_cache",
    "dist", "build", "coverage", ".tox", ".eggs",
}


def _is_skill_file(path: Path) -> bool:
    """Return True for any file the v2 skill-scanner pipeline can process.

    Accepts:
      - any .md / .html / .htm  (skill, subagent, rules, or manifest file)
      - plugin.json, mcp.json, .mcp.json  (plugin / MCP manifests)
    """
    name = path.name.lower()
    if name in _MANIFEST_NAMES:
        return True
    return path.suffix.lower() in _SKILL_EXTENSIONS


def _discover_skill_files(repo_path: str) -> List[Path]:
    root  = Path(repo_path)
    found: List[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for filename in filenames:
            candidate = Path(dirpath) / filename
            if _is_skill_file(candidate):
                found.append(candidate)
    return found


def _map_severity(raw: str) -> ScanSeverity:
    return _SEVERITY_MAP.get(str(raw).upper(), ScanSeverity.LOW)


# ---------------------------------------------------------------------------
# Structured-output helpers — build the per-framework sections that appear
# alongside metadata in the final /scan response.
# ---------------------------------------------------------------------------

# OWASP LLM Top 10 (2025) display names
_LLM_NAMES: Dict[str, str] = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM03": "Supply Chain",
    "LLM04": "Data and Model Poisoning",
    "LLM05": "Improper Output Handling",
    "LLM06": "Excessive Agency",
    "LLM07": "System Prompt Leakage",
    "LLM08": "Vector and Embedding Weaknesses",
    "LLM09": "Misinformation",
    "LLM10": "Unbounded Consumption",
}

# OWASP Agentic AI Top 10 display names
_ASI_NAMES: Dict[str, str] = {
    "ASI01": "Agent Goal Hijack",
    "ASI02": "Excessive Agency / Tool Misuse",
    "ASI03": "Identity & Privilege Abuse",
    "ASI04": "Resource & Supply Chain Compromise",
    "ASI05": "Unsafe Execution Environment",
    "ASI06": "Memory & Context Poisoning",
    "ASI07": "Unsafe Inter-Agent Communication",
    "ASI08": "Inadequate Audit Trail",
    "ASI09": "Overreliance on AI Judgment",
    "ASI10": "Model Theft & Exfiltration",
}

# EU AI Act high-risk AI requirements → ASI/OWASP LLM coverage
# Article numbers reference the EU AI Act (Regulation 2024/1689).
_EU_AI_ACT_ARTICLES: List[Dict] = [
    {
        "id":   "Art. 9",
        "name": "Risk Management System",
        "asi":  {"ASI01", "ASI02", "ASI03"},
        "llm":  {"LLM01", "LLM06"},
    },
    {
        "id":   "Art. 10",
        "name": "Data Governance",
        "asi":  {"ASI04", "ASI05"},
        "llm":  {"LLM03", "LLM04"},
    },
    {
        "id":   "Art. 12",
        "name": "Logging & Traceability",
        "asi":  {"ASI08"},
        "llm":  {"LLM09"},
    },
    {
        "id":   "Art. 14",
        "name": "Human Oversight",
        "asi":  {"ASI02", "ASI03"},
        "llm":  {"LLM06"},
    },
    {
        "id":   "Art. 15",
        "name": "Cybersecurity Controls",
        "asi":  {"ASI01", "ASI02", "ASI03", "ASI04", "ASI05", "ASI06"},
        "llm":  {"LLM01", "LLM02", "LLM03", "LLM05", "LLM06", "LLM07"},
    },
]

_SEV_PENALTY_EU: Dict[str, int] = {
    "critical": 20, "high": 12, "medium": 5, "low": 2, "info": 0,
}
_SEV_RANK_EU: Dict[str, int] = {
    "critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0,
}


def _eu_ai_act_status(score: int) -> str:
    if score >= 85:
        return "COMPLIANT"
    elif score >= 60:
        return "AT_RISK"
    return "NON_COMPLIANT"


def _build_eu_ai_act_mapping(findings: List[ScanFinding]) -> Dict[str, Any]:
    """Map findings to EU AI Act article requirements and compute compliance scores."""
    art_sevs: Dict[str, List[str]] = {a["name"]: [] for a in _EU_AI_ACT_ARTICLES}

    for f in findings:
        sev = (
            f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        ).lower()
        asi = f.column or ""
        llm = f.code   or ""
        for art in _EU_AI_ACT_ARTICLES:
            if asi in art["asi"] or llm in art["llm"]:
                art_sevs[art["name"]].append(sev)

    items = []
    total_score = 0
    for art in _EU_AI_ACT_ARTICLES:
        penalty = sum(_SEV_PENALTY_EU.get(s, 0) for s in art_sevs[art["name"]])
        score   = max(0, 100 - penalty)
        total_score += score
        items.append({
            "name":    art["name"],
            "article": art["id"],
            "gap":     100 - score,
            "status":  _eu_ai_act_status(score),
        })

    overall = total_score // len(_EU_AI_ACT_ARTICLES) if _EU_AI_ACT_ARTICLES else 100
    return {"overall_progress": overall, "items": items}


def _build_owasp_mapping(findings: List[ScanFinding]) -> List[Dict[str, str]]:
    """Return one entry per unique OWASP LLM / Agentic ID seen in findings,
    carrying the worst severity observed for that ID."""
    all_names = {**_LLM_NAMES, **_ASI_NAMES}
    worst: Dict[str, int] = {}  # id -> severity rank

    for f in findings:
        sev  = (
            f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        ).lower()
        rank = _SEV_RANK_EU.get(sev, 0)
        for fid in (f.code, f.column):
            if fid and fid in all_names:
                if rank > worst.get(fid, -1):
                    worst[fid] = rank

    rank_label = {4: "CRITICAL", 3: "HIGH", 2: "MEDIUM", 1: "LOW", 0: "INFO"}
    return [
        {"id": fid, "name": all_names[fid], "severity": rank_label.get(r, "INFO")}
        for fid, r in sorted(worst.items())
    ]


def _build_issue_by_scanner(
    chart_data:  Dict[str, Any],
    eu_overall:  int,
) -> List[Dict[str, int]]:
    """Compute a single-object list with one overall % score per framework."""
    nist_scores  = chart_data.get("nist_function_scores",  {})
    atlas_scores = chart_data.get("atlas_tactic_scores",   {})
    asi_status   = chart_data.get("owasp_agentic_status",  {})

    nist_overall  = (
        int(sum(nist_scores.values())  / len(nist_scores))  if nist_scores  else 100
    )
    mitre_overall = (
        int(sum(atlas_scores.values()) / len(atlas_scores)) if atlas_scores else 100
    )
    _pen = {"CRITICAL": 20, "HIGH": 12, "MEDIUM": 5, "LOW": 2, "INFO": 0}
    owasp_overall = max(
        0, 100 - sum(_pen.get(s, 0) for s in asi_status.values())
    )
    return [{
        "eu_ai_act":  eu_overall,
        "nist_act":   nist_overall,
        "mitre_act":  mitre_overall,
        "owasp_act":  owasp_overall,
    }]


# Finding converters
# Framework IDs are carried across available ScanFinding fields:
#   code   → OWASP LLM Top 10 ID  (e.g. "LLM01")
#   column → OWASP Agentic ID      (e.g. "ASI01")
#   url    → NIST AI RMF controls  (e.g. "MEASURE 2.7 | MS-2.7-007")
#   deny   → MITRE ATLAS IDs       (e.g. ["AML.T0068", "AML.T0051.001"])
# The description also embeds a compact framework annotation so it is
# self-contained when viewed in the UI.

def _framework_suffix(asi_id: Optional[str],
                      nist_rmf: List[str],
                      atlas_ids: List[str]) -> str:
    """Return a compact annotation string, or empty string if nothing present."""
    parts = []
    if asi_id:
        parts.append(asi_id)
    if nist_rmf:
        parts.append("NIST: " + ", ".join(nist_rmf))
    if atlas_ids:
        parts.append("ATLAS: " + ", ".join(atlas_ids))
    return (" | " + " | ".join(parts)) if parts else ""


def _provider_label(asi_id: Optional[str], nist_rmf: List[str], atlas_ids: List[str]) -> Optional[str]:
    providers = []
    if atlas_ids:
        providers.append("MITRE ATLAS")
    if nist_rmf:
        providers.append("NIST AI RMF")
    if asi_id:
        providers.append("EU AI Act")
    return ", ".join(providers) if providers else None


def _build_code_block(source_text: Optional[str], line: Optional[str], fallback: Optional[str]) -> Optional[str]:
    if source_text and line:
        try:
            line_number = int(line)
        except (TypeError, ValueError):
            line_number = 0
        if line_number > 0:
            lines = source_text.splitlines()
            start = max(0, line_number - 3)
            end = min(len(lines), line_number + 2)
            if start < end:
                return "\n".join(lines[start:end])
    return fallback


def _layer1_to_scan_finding(
    finding: "Layer1Finding", file_path: str, source_text: Optional[str] = None
) -> ScanFinding:
    policy = f"{finding.detector}:{finding.type}" if finding.detector else finding.type

    # Base description
    desc_parts = []
    if finding.owasp_id:
        desc_parts.append(f"[{finding.owasp_id}]")
    desc_parts.append(finding.type.replace("_", " ").title())
    desc_parts.append("—")
    desc_parts.append(finding.recommended_action)
    if finding.harm_category:
        desc_parts.append(f"(harm: {finding.harm_category})")

    # Framework data: prefer pre-set attributes (Pydantic v2 with extended model),
    # fall back to a direct frameworks.lookup() for containers running the v1 model
    # where enrich() attribute-mutation silently fails.
    _m = frameworks.lookup(finding.type, getattr(finding, "owasp_id", None))
    asi_id    = getattr(finding, "asi_id",    None) or (_m.asi_id    if _m else None)
    nist_rmf  = list(getattr(finding, "nist_rmf",  None) or (_m.nist_rmf  if _m else []))
    atlas_ids = list(getattr(finding, "atlas_ids", None) or (_m.atlas_ids if _m else []))
    description = " ".join(desc_parts) + _framework_suffix(asi_id, nist_rmf, atlas_ids)

    matched = finding.matched_snippet or finding.decoded_payload
    line = str(finding.line) if finding.line is not None else None

    return ScanFinding(
        policy=policy,
        severity=_map_severity(finding.severity),
        description=description,
        code=finding.owasp_id,                          # OWASP LLM Top 10 ID
        column=asi_id,                                   # OWASP Agentic Top 10 ID
        url=" | ".join(nist_rmf) if nist_rmf else None,  # NIST AI RMF controls
        deny=list(atlas_ids) if atlas_ids else None,     # MITRE ATLAS IDs
        match=matched[:500] if matched else None,
        file=file_path,
        line=line,
        code_block=_build_code_block(source_text, line, matched or description),
        provider=_provider_label(asi_id, nist_rmf, atlas_ids),
    )


def _layer2_to_scan_finding(
    finding: "Layer2Finding", file_path: str, source_text: Optional[str] = None
) -> ScanFinding:
    policy = f"llm:{finding.type}"

    desc = finding.description
    if finding.harm_category:
        desc = f"[{finding.harm_category}] {desc}"

    asi_id    = getattr(finding, "asi_id",    None)
    nist_rmf  = getattr(finding, "nist_rmf",  []) or []
    atlas_ids = getattr(finding, "atlas_ids", []) or []
    # Fallback to direct lookup if the model didn't carry framework fields
    if not any([asi_id, nist_rmf, atlas_ids]):
        _m = frameworks.lookup(getattr(finding, "type", None), getattr(finding, "owasp_id", None))
        if _m:
            asi_id    = _m.asi_id
            nist_rmf  = list(_m.nist_rmf)
            atlas_ids = list(_m.atlas_ids)
    description = desc + _framework_suffix(asi_id, nist_rmf, atlas_ids)

    location = getattr(finding, "location", None)
    line = str(location) if location else None
    line_number = line.removeprefix("line ").strip() if line else None

    return ScanFinding(
        policy=policy,
        severity=_map_severity(finding.severity),
        description=description,
        code=finding.owasp_id,
        column=asi_id,
        url=" | ".join(nist_rmf) if nist_rmf else None,
        deny=list(atlas_ids) if atlas_ids else None,
        file=file_path,
        line=line,
        code_block=_build_code_block(source_text, line_number, desc),
        provider=_provider_label(asi_id, nist_rmf, atlas_ids),
    )

# Scanner implementation

class SkillScanner(BaseScanner):
    """
    AI-agent skill file security scanner (v2 — with framework crosswalk).

    Runs the full v2 detector pipeline from the Skills Test Suite and
    exposes it through the standard Zyloch BaseScanner interface.
    """

    def __init__(self) -> None:
        super().__init__("skill_scanner")

    # Public interface    

    def scan(self, request: ScanRequest) -> ScanResponse:
        start_time = time.time()
        logger.info(
            "[SkillScanner] Scan started | scan_id=%s | repo=%s",
            request.scan_id,
            request.repo_path,
        )

        if not _DETECTORS_AVAILABLE:
            return self._create_error_response(
                request.scan_id,
                "Skill scanner detectors are not available. "
                "Ensure scanner_core.detectors and scanner_core.helpers are installed.",
            )

        try:
            # ── Step 1: Discover skill files ────────────────────────────
            skill_files = _discover_skill_files(request.repo_path)

            if not skill_files:
                logger.info(
                    "[SkillScanner] No skill/manifest files found in %s — skipping",
                    request.repo_path,
                )
                return self._create_success_response(
                    request.scan_id,
                    ScanResult(
                        scanner_type=self.scanner_type,
                        status=ScanStatus.COMPLETED,
                        findings=[],
                        scanned_files=[],
                        scan_duration=time.time() - start_time,
                    ),
                )

            logger.info(
                "[SkillScanner] Discovered %d skill/manifest file(s)", len(skill_files)
            )

            # ── Step 2: Check optional LLM gate ────────────────────────
            enable_llm: bool = bool(
                (request.metadata or {}).get("enable_llm", False)
            )
            if enable_llm:
                try:
                    from app import llm_analyzer as _llm_mod  # noqa: F401
                    logger.info("[SkillScanner] Layer 2 (LLM) analysis enabled")
                except ImportError:
                    logger.warning(
                        "[SkillScanner] enable_llm=True but llm_analyzer unavailable; "
                        "Layer 2 disabled for this run"
                    )
                    enable_llm = False

            # ── Step 3: Scan each file ──────────────────────────────────
            all_findings: List[ScanFinding] = []
            scanned_files: List[str] = []
            disabled_policies = (request.metadata or {}).get("disabled_policies", {})

            for file_path in skill_files:
                rel_path = str(file_path.relative_to(request.repo_path))
                file_findings = self._scan_file(
                    file_path, rel_path, enable_llm=enable_llm
                )
                all_findings.extend(file_findings)
                scanned_files.append(rel_path)

            # ── Step 4: Apply disabled-policy filter ────────────────────
            if disabled_policies:
                before = len(all_findings)
                all_findings = [
                    f for f in all_findings
                    if not (disabled_policies.get(f.code or "") is False)
                ]
                removed = before - len(all_findings)
                if removed:
                    logger.info(
                        "[SkillScanner] Suppressed %d finding(s) via disabled_policies",
                        removed,
                    )

            # ── Step 5: Scoring ─────────────────────────────────────────
            overall_score = 100.0
            file_scores: Dict[str, Any] = {}
            try:
                findings_dicts = [
                    {
                        "policy":      f.policy or "",
                        "severity":    (
                            f.severity.value
                            if hasattr(f.severity, "value")
                            else str(f.severity)
                        ),
                        "description": f.description,
                        "code":        f.code,
                        "file":        f.file,
                        "line":        f.line,
                    }
                    for f in all_findings
                ]
                adapter = OPABasedScoreAdapter()
                overall_score, file_scores = adapter.calculate_score(
                    findings=findings_dicts,
                    scanned_files=scanned_files,
                )
                logger.info("[SkillScanner] Security score: %.2f", overall_score)
            except Exception as score_err:
                logger.warning(
                    "[SkillScanner] Scoring failed (non-fatal): %s", score_err
                )

            duration = time.time() - start_time

            # Severity breakdown
            sev_counts: Dict[str, int] = {}
            for f in all_findings:
                sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
                sev_counts[sev] = sev_counts.get(sev, 0) + 1
            if sev_counts:
                logger.info("[SkillScanner] Severity breakdown: %s", sev_counts)

            # Chart data — per-tactic / per-NIST-function scores + per-ASI status
            chart_data    = frameworks.compute_chart_data(all_findings)
            nist_scores   = chart_data.get("nist_function_scores",  {})
            atlas_scores  = chart_data.get("atlas_tactic_scores",   {})

            # Structured framework sections for the /scan response
            eu_act_mapping  = _build_eu_ai_act_mapping(all_findings)
            owasp_mapping   = _build_owasp_mapping(all_findings)
            issue_by_scanner = _build_issue_by_scanner(
                chart_data, eu_act_mapping["overall_progress"]
            )

            metadata: Dict[str, Any] = {
                "total_skill_files":  len(scanned_files),
                "total_findings":     len(all_findings),
                "overall_score":      overall_score,
                "file_scores":        file_scores,
                "llm_layer_enabled":  enable_llm,
                "severity_breakdown": sev_counts,
                "frameworks":         ["OWASP LLM Top 10", "OWASP Agentic Top 10",
                                       "NIST AI RMF 1.0 + GenAI Profile",
                                       "MITRE ATLAS v5.6.0"],
                # ── Structured chart / compliance sections ─────────────────
                "issue_by_scanner":   issue_by_scanner,
                "eu_ai_act_mapping":  eu_act_mapping,
                "nist_ai_rmf_mapping": {
                    "govern":  nist_scores.get("GOVERN",  100),
                    "map":     nist_scores.get("MAP",     100),
                    "measure": nist_scores.get("MEASURE", 100),
                    "manage":  nist_scores.get("MANAGE",  100),
                },
                "mitre_atlas_mapping": {
                    "reconnaissance":     atlas_scores.get("Reconnaissance",     100),
                    "initial_access":     atlas_scores.get("Initial Access",     100),
                    "credential_access":  atlas_scores.get("Credential Access",  100),
                    "discovery":          atlas_scores.get("Discovery",          100),
                    "collection":         atlas_scores.get("Collection",         100),
                    "exfiltration":       atlas_scores.get("Exfiltration",       100),
                    "defense_evasion":    atlas_scores.get("Defense Evasion",    100),
                    "persistence":        atlas_scores.get("Persistence",        100),
                    "privilege_escalation": atlas_scores.get("Privilege Escalation", 100),
                    "execution":          atlas_scores.get("Execution",          100),
                    "impact":             atlas_scores.get("Impact",             100),
                },
                "owasp_mapping":      owasp_mapping,
            }

            logger.info(
                "[SkillScanner] Scan complete | scan_id=%s | files=%d "
                "| findings=%d | duration=%.2fs",
                request.scan_id,
                len(scanned_files),
                len(all_findings),
                duration,
            )

            return self._create_success_response(
                request.scan_id,
                ScanResult(
                    scanner_type=self.scanner_type,
                    status=ScanStatus.COMPLETED,
                    findings=all_findings,
                    scanned_files=scanned_files,
                    scan_duration=duration,
                    metadata=metadata,
                ),
            )

        except Exception as exc:
            logger.error(
                "[SkillScanner] Scan failed after %.2fs: %s",
                time.time() - start_time,
                exc,
                exc_info=True,
            )
            return self._create_error_response(
                request.scan_id, f"Skill scanner failed: {exc}"
            )

    # Internal helpers

    def _scan_file(
        self,
        file_path: Path,
        rel_path: str,
        enable_llm: bool = False,
    ) -> List[ScanFinding]:
        """Run the full v2 detector pipeline on one file and return ScanFindings."""
        try:
            raw = file_path.read_bytes()
        except OSError as exc:
            logger.warning("[SkillScanner] Cannot read %s: %s", rel_path, exc)
            return []

        text     = raw.decode("utf-8", errors="replace")
        filename = file_path.name
        suffix   = file_path.suffix.lower()

        is_html            = suffix in {".html", ".htm"}
        is_plugin_manifest = bundle_detector.is_plugin_manifest(filename)
        is_mcp_manifest    = filename.lower() in {"mcp.json", ".mcp.json"}

        layer1: List[Layer1Finding] = []

        def _safe(step: str, fn):
            try:
                return list(fn() or [])
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "[SkillScanner] Detector '%s' raised on %s: %s",
                    step, rel_path, exc,
                )
                return []

        # ── Step 1: Unicode smuggling ────────────────────────────────────
        unicode_findings = _safe("unicode_detector", lambda: unicode_detector.detect(text))
        unicode_findings = _safe(
            "allowlist:unicode",
            lambda: allowlist.filter_findings(text, unicode_findings),
        )
        layer1.extend(unicode_findings)

        # ── Step 2: Tokenizer-merge injection ───────────────────────────
        layer1.extend(_safe("tokenizer", lambda: tokenizer.detect(text)))

        # ── Step 3: HTML-specific checks (html files only) ───────────────
        if is_html:
            layer1.extend(_safe("html_detector", lambda: html_detector.detect(text)))

        # ── Step 4: OWASP LLM Top 10 pattern matching ────────────────────
        layer1.extend(_safe("owasp_detector", lambda: owasp_detector.detect(text)))

        # ── Step 5: Cross-region fragmented payload assembly ─────────────
        layer1.extend(_safe("fragmented", lambda: fragmented.detect(text)))

        # ── Step 5a: Self-replication / worm (ATLAS AML.T0061) ───────────
        layer1.extend(
            _safe("self_replication_detector",
                  lambda: self_replication_detector.detect(text))
        )

        # ── Step 5b: Harness / trusted-output impersonation (AML.T0067) ──
        layer1.extend(
            _safe("harness_impersonation_detector",
                  lambda: harness_impersonation_detector.detect(text))
        )

        # ── Step 5c: Agentic behaviour (ASI02/03/06) ─────────────────────
        layer1.extend(
            _safe("agentic_detector",
                  lambda: agentic_detector.detect(text))
        )

        # ── Step 5d: Data-exfiltration channels (AML.T0025) ──────────────
        layer1.extend(
            _safe("exfiltration_detector",
                  lambda: exfiltration_detector.detect(text))
        )

        # ── Step 6: Skill frontmatter trust-elevation advisories ──────────
        layer1.extend(
            _safe("skill_frontmatter_detector",
                  lambda: skill_frontmatter_detector.detect(text))
        )

        # ── Step 7: Config-target advisories ──────────────────────────────
        layer1.extend(
            _safe("config_target_detector",
                  lambda: config_target_detector.detect(text))
        )

        # ── Step 7a: Plugin manifest (plugin.json only) ───────────────────
        if is_plugin_manifest:
            layer1.extend(
                _safe("plugin_manifest_detector",
                      lambda: plugin_manifest_detector.detect(text))
            )

        # ── Step 7b: MCP manifest (mcp.json / .mcp.json only) ────────────
        if is_mcp_manifest:
            layer1.extend(
                _safe("mcp_manifest_detector",
                      lambda: mcp_manifest_detector.detect_mcp_json(text))
            )

        # ── Step 8: Final allowlist pass ──────────────────────────────────
        layer1 = _safe(
            "allowlist:final",
            lambda: allowlist.filter_findings(text, layer1),
        )

        # ── Step 9: Payload decoder — scan + enrich ───────────────────────
        layer1.extend(_safe("payload_decoder:scan", lambda: payload_decoder.scan(text)))
        _safe("payload_decoder:enrich", lambda: payload_decoder.enrich(layer1))

        # ── Step 9a: Framework crosswalk — back-fill asi_id / nist_rmf /
        #             atlas_ids on every Layer 1 finding.
        _safe("frameworks:layer1", lambda: frameworks.enrich(layer1))

        # ── Convert Layer 1 → Zyloch ScanFinding ─────────────────────────
        findings: List[ScanFinding] = [
            _layer1_to_scan_finding(f, rel_path, text) for f in layer1
        ]

        # ── Step 10: Optional Layer 2 LLM analysis ───────────────────────
        if enable_llm:
            try:
                from app import llm_analyzer

                result = llm_analyzer.analyze(
                    text,
                    filename,
                    layer1_findings=layer1,
                    bundle_context="",
                )
                # Back-fill framework crosswalk on Layer 2 findings too
                _safe("frameworks:layer2", lambda: frameworks.enrich(result.findings))
                for lf in result.findings:
                    findings.append(_layer2_to_scan_finding(lf, rel_path, text))
                if result.warning:
                    logger.warning(
                        "[SkillScanner] LLM warning for %s: %s",
                        rel_path,
                        result.warning,
                    )
            except Exception as llm_exc:
                logger.warning(
                    "[SkillScanner] LLM analysis failed for %s (non-fatal): %s",
                    rel_path,
                    llm_exc,
                )

        if findings:
            logger.info("[SkillScanner] %s → %d finding(s)", rel_path, len(findings))

        return findings



# Module-level entry point — matches the scan_<type>() pattern used by every
# other Zyloch microservice so the scan controller can call it uniformly.


def scan_skill(request: ScanRequest) -> ScanResponse:
    return SkillScanner().scan(request)



# CLI for ad-hoc testing


if __name__ == "__main__":
    import argparse, json as _json

    parser = argparse.ArgumentParser(description="Skill Security Scanner v2")
    parser.add_argument("--repo-path",  required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--scan-id",    required=True)
    parser.add_argument("--enable-llm", action="store_true", default=False)
    args = parser.parse_args()

    resp = scan_skill(ScanRequest(
        repo_path=args.repo_path,
        output_dir=args.output_dir,
        scan_id=args.scan_id,
        metadata={"enable_llm": args.enable_llm},
    ))
    print(_json.dumps(resp.dict(), indent=2, default=str))
