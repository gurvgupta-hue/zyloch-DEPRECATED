"""Framework crosswalk — map every finding to the security controls it satisfies.

The scanner's rules are grounded in four public frameworks:

  - OWASP LLM Top 10 (2025)          → carried on each finding as `owasp_id`
  - OWASP Agentic Top 10 (ASI01-10)  → `asi_id`        (this module)
  - NIST AI RMF + GenAI Profile      → `nist_rmf`       (this module)
  - MITRE ATLAS (v5.6.0)             → `atlas_ids`      (this module)

Rather than scatter framework IDs across every detector, we keep a single
auditable crosswalk here and back-fill the fields after detection runs
(same pattern as payload_decoder.enrich). One table = one place a client or
auditor reviews to confirm "all scan rules comply with the frameworks".

Mapping is keyed on the finding `type` (most specific). Anything without a
type-level entry falls back to its `owasp_id` so nothing ships untagged.

References:
  NIST AI 100-1 (AI RMF 1.0) · https://nvlpubs.nist.gov/nistpubs/ai/nist.ai.100-1.pdf
  NIST AI 600-1 (GenAI Profile) · https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf
  MITRE ATLAS · https://atlas.mitre.org  (data of record: atlas-data v5.6.0)
  OWASP Agentic Top 10 (ASI) · https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass(frozen=True)
class Mapping:
    """Framework controls a finding maps to."""
    asi_id: Optional[str] = None          # OWASP Agentic Top 10 (ASI01-ASI10)
    nist_rmf: List[str] = field(default_factory=list)   # AI RMF subcategories + GenAI actions
    atlas_ids: List[str] = field(default_factory=list)  # ATLAS techniques (+ mitigations)


# ── Fallback by OWASP LLM id ────────────────────────────────────────────
# Used when a finding `type` has no specific entry below. Keeps every rule
# grounded even if a new detector ships before its type is crosswalked.
_BY_OWASP: Dict[str, Mapping] = {
    "LLM01": Mapping("ASI01", ["MEASURE 2.7", "MS-2.7-007"], ["AML.T0051", "AML.T0054"]),
    "LLM02": Mapping("ASI03", ["MEASURE 2.7", "MEASURE 2.10"], ["AML.T0057", "AML.T0024"]),
    "LLM03": Mapping("ASI04", ["MAP 4.1", "MANAGE 3.1", "MG-3.1-002"], ["AML.T0010"]),
    "LLM04": Mapping("ASI06", ["MEASURE 2.7", "MAP 5.1"], ["AML.T0020", "AML.T0070"]),
    "LLM05": Mapping("ASI05", ["MEASURE 2.7"], ["AML.T0050", "AML.T0011"]),
    "LLM06": Mapping("ASI02", ["MAP 4.2", "MEASURE 2.7"], ["AML.T0053"]),
    "LLM07": Mapping("ASI03", ["MEASURE 2.7"], ["AML.T0056", "AML.T0069"]),
    "LLM08": Mapping("ASI06", ["MEASURE 2.7"], ["AML.T0070"]),
    "LLM09": Mapping("ASI08", ["MEASURE 2.6"], ["AML.T0048"]),
    "LLM10": Mapping("ASI04", ["MANAGE 2.x"], ["AML.T0029"]),
}


# ── Per-finding-type crosswalk (authoritative) ──────────────────────────
# Each key is a finding `type` emitted somewhere in app/detectors. Edit this
# table when adding a detector so the new rule ships fully crosswalked.
_BY_TYPE: Dict[str, Mapping] = {
    # ── unicode_detector ──
    "TAG_BLOCK_SMUGGLING":   Mapping("ASI01", ["MEASURE 2.7", "MS-2.7-007"], ["AML.T0068", "AML.T0051.001", "AML.M0015"]),
    "ZERO_WIDTH_BINARY":     Mapping("ASI01", ["MEASURE 2.7", "MS-2.7-007"], ["AML.T0068", "AML.M0015"]),
    "VARIATION_SELECTORS":   Mapping("ASI01", ["MEASURE 2.7"], ["AML.T0068", "AML.M0015"]),
    "INVISIBLE_MATH_OPERATOR": Mapping("ASI01", ["MEASURE 2.7"], ["AML.T0068"]),
    "EMOJI_SMUGGLING":       Mapping("ASI01", ["MEASURE 2.7"], ["AML.T0068"]),
    "BIDI_OVERRIDE":         Mapping("ASI01", ["MEASURE 2.7"], ["AML.T0068"]),
    "OTHER_INVISIBLE":       Mapping("ASI01", ["MEASURE 2.7"], ["AML.T0068"]),
    "BOM_INSIDE_FILE":       Mapping("ASI01", ["MEASURE 2.7"], ["AML.T0068"]),

    # ── owasp_detector (type prefixed with the OWASP id) handled by fallback ──

    # ── tokenizer ──
    "TOKEN_MERGE_INJECTION": Mapping("ASI01", ["MEASURE 2.7", "MS-2.7-007"], ["AML.T0068", "AML.T0051"]),

    # ── fragmented ──
    "FRAGMENTED_PAYLOAD":    Mapping("ASI01", ["MEASURE 2.7", "MS-2.7-007"], ["AML.T0068", "AML.T0051"]),

    # ── payload_decoder ──
    "HTML_ENTITY_PAYLOAD":   Mapping("ASI01", ["MEASURE 2.7"], ["AML.T0068"]),
    "BASE64_PAYLOAD":        Mapping("ASI01", ["MEASURE 2.7"], ["AML.T0068"]),
    "URL_ENCODED_PAYLOAD":   Mapping("ASI01", ["MEASURE 2.7"], ["AML.T0068"]),

    # ── html_detector ──
    "SCRIPT_WITH_INSTRUCTIONS": Mapping("ASI05", ["MEASURE 2.7"], ["AML.T0051", "AML.T0050"]),
    "EVENT_HANDLER_PAYLOAD":    Mapping("ASI05", ["MEASURE 2.7"], ["AML.T0051", "AML.T0050"]),
    "HIDDEN_ELEMENT_INSTRUCTIONS": Mapping("ASI01", ["MEASURE 2.7"], ["AML.T0051.001", "AML.T0068"]),
    "EXTERNAL_FETCH":        Mapping("ASI04", ["MAP 4.1", "MEASURE 2.7"], ["AML.T0025"]),
    "DATA_ATTR_INSTRUCTIONS": Mapping("ASI01", ["MEASURE 2.7"], ["AML.T0051.001", "AML.T0068"]),
    "HTML_ENTITY_CLUSTER":   Mapping("ASI01", ["MEASURE 2.7"], ["AML.T0068"]),
    "BASE64_ATTRIBUTE":      Mapping("ASI01", ["MEASURE 2.7"], ["AML.T0068"]),
    "CSS_CONTENT_INJECTION": Mapping("ASI01", ["MEASURE 2.7"], ["AML.T0051.001", "AML.T0068"]),
    "META_SUSPICIOUS":       Mapping("ASI04", ["MEASURE 2.7"], ["AML.T0051.001"]),
    "EXTERNAL_FRAMED_CONTENT": Mapping("ASI04", ["MAP 4.1", "MANAGE 3.1"], ["AML.T0010.001", "AML.T0051.001"]),

    # ── skill_frontmatter_detector (trust elevation = agentic tool/privilege) ──
    "FRONTMATTER_WILDCARD_TOOLS":   Mapping("ASI02", ["MAP 4.2", "MEASURE 2.7"], ["AML.T0053", "AML.M0028"]),
    "FRONTMATTER_BYPASS_PERMISSIONS": Mapping("ASI03", ["MAP 4.2", "MEASURE 2.7"], ["AML.T0053", "AML.M0026", "AML.M0029"]),
    "FRONTMATTER_EMBEDDED_MCP_SERVER": Mapping("ASI04", ["MAP 4.1", "MANAGE 3.1", "MG-3.1-002"], ["AML.T0010.001"]),
    "FRONTMATTER_HOOKS_DECLARED":   Mapping("ASI02", ["MAP 4.2", "MEASURE 2.7"], ["AML.T0053", "AML.M0028"]),
    "FRONTMATTER_BROAD_TRIGGER_DESCRIPTION": Mapping("ASI01", ["MAP 1.1", "MAP 5.1"], ["AML.T0051", "AML.T0066"]),
    "FRONTMATTER_NAME_HOMOGLYPH":   Mapping("ASI09", ["MAP 4.1", "MEASURE 2.7"], ["AML.T0010.001", "AML.T0068"]),

    # ── config_target_detector ──
    "CONFIG_TARGET_VSCODE_SETTINGS": Mapping("ASI03", ["MAP 4.2", "MEASURE 2.7"], ["AML.T0053", "AML.M0028"]),
    "CONFIG_TARGET_CLAUDE_SETTINGS": Mapping("ASI03", ["MAP 4.2", "MEASURE 2.7"], ["AML.T0053", "AML.M0028"]),
    "CONFIG_TARGET_CURSOR_RULES":    Mapping("ASI06", ["MAP 4.2"], ["AML.T0051.001", "AML.T0061"]),
    "CONFIG_TARGET_COPILOT_INSTRUCTIONS": Mapping("ASI06", ["MAP 4.2"], ["AML.T0051.001", "AML.T0061"]),
    "CONFIG_TARGET_AGENTS_MD":       Mapping("ASI06", ["MAP 4.2"], ["AML.T0051.001"]),
    "CONFIG_TARGET_MCP_JSON":        Mapping("ASI04", ["MAP 4.1", "MANAGE 3.1"], ["AML.T0010.001"]),
    "CONFIG_TARGET_SECRETS":         Mapping("ASI03", ["MEASURE 2.7", "MEASURE 2.10"], ["AML.T0055", "AML.T0057"]),
    "CONFIG_TARGET_ENV_FILE":        Mapping("ASI03", ["MEASURE 2.7", "MEASURE 2.10"], ["AML.T0055", "AML.T0057"]),
    "CONFIG_TARGET_GIT_INTERNALS":   Mapping("ASI05", ["MAP 4.2"], ["AML.T0010.001"]),
    "CONFIG_TARGET_HUSKY":           Mapping("ASI05", ["MAP 4.2"], ["AML.T0010.001"]),
    "AUTOAPPROVE_VSCODE":            Mapping("ASI03", ["MAP 4.2", "MEASURE 2.7"], ["AML.T0053", "AML.M0026"]),
    "AUTOAPPROVE_CLI_FLAG":          Mapping("ASI03", ["MAP 4.2", "MEASURE 2.7"], ["AML.T0053", "AML.M0026"]),
    "AUTOAPPROVE_BYPASS_STRING":     Mapping("ASI03", ["MAP 4.2", "MEASURE 2.7"], ["AML.T0053", "AML.M0026"]),
    "AUTOAPPROVE_PERMISSIONS_ALLOW": Mapping("ASI03", ["MAP 4.2", "MEASURE 2.7"], ["AML.T0053", "AML.M0028"]),
    "DEP_PIP_INDEX_OVERRIDE":        Mapping("ASI04", ["MAP 4.1", "MANAGE 3.1", "MG-3.1-002"], ["AML.T0010.001", "AML.T0011.001"]),
    "DEP_PIP_INDEX_CONFIG":          Mapping("ASI04", ["MAP 4.1", "MANAGE 3.1", "MG-3.1-002"], ["AML.T0010.001", "AML.T0011.001"]),
    "DEP_NPM_REGISTRY_OVERRIDE":     Mapping("ASI04", ["MAP 4.1", "MANAGE 3.1", "MG-3.1-002"], ["AML.T0010.001", "AML.T0011.001"]),
    "DEP_CURL_PIPE_SHELL":           Mapping("ASI05", ["MEASURE 2.7"], ["AML.T0010.001", "AML.T0050"]),
    "DEP_WGET_PIPE_SHELL":           Mapping("ASI05", ["MEASURE 2.7"], ["AML.T0010.001", "AML.T0050"]),

    # ── plugin_manifest_detector ──
    "PLUGIN_HOOKS_DECLARED":         Mapping("ASI02", ["MAP 4.2", "MEASURE 2.7"], ["AML.T0053", "AML.M0028"]),
    "PLUGIN_EMBEDDED_MCP_SERVER":    Mapping("ASI04", ["MAP 4.1", "MANAGE 3.1", "MG-3.1-002"], ["AML.T0010.001"]),
    "PLUGIN_WILDCARD_PERMISSIONS":   Mapping("ASI03", ["MAP 4.2", "MEASURE 2.7"], ["AML.T0053", "AML.M0028"]),
    "PLUGIN_WILDCARD_TOOLS":         Mapping("ASI02", ["MAP 4.2", "MEASURE 2.7"], ["AML.T0053", "AML.M0028"]),
    "PLUGIN_PUBLISHER_SPOOF":        Mapping("ASI09", ["MAP 4.1", "GOVERN 6.1"], ["AML.T0010.001"]),
    "PLUGIN_NAME_HOMOGLYPH":         Mapping("ASI09", ["MAP 4.1"], ["AML.T0010.001", "AML.T0068"]),
    "PLUGIN_BROAD_TRIGGER_DESCRIPTION": Mapping("ASI01", ["MAP 1.1", "MAP 5.1"], ["AML.T0051"]),
    "PLUGIN_MISSING_METADATA":       Mapping("ASI04", ["MAP 4.1", "GOVERN 6.1", "GV-6.1-007"], ["AML.T0010.001", "AML.M0023"]),

    # ── mcp_manifest_detector ──
    "MCP_RISKY_LAUNCHER":            Mapping("ASI04", ["MAP 4.1", "MANAGE 3.1"], ["AML.T0010.001", "AML.T0050"]),
    "MCP_RISKY_ARGS":                Mapping("ASI04", ["MAP 4.1", "MANAGE 3.1", "MG-3.1-002"], ["AML.T0010.001", "AML.T0011.001"]),
    "MCP_RISKY_ENV":                 Mapping("ASI03", ["MEASURE 2.7", "MEASURE 2.10"], ["AML.T0055", "AML.T0057"]),
    "MCP_REMOTE_URL":                Mapping("ASI07", ["MAP 4.1", "MANAGE 3.1"], ["AML.T0010.001", "AML.T0025"]),

    # ── self_replication_detector (NEW) ──
    "PROMPT_SELF_REPLICATION":       Mapping("ASI06", ["MEASURE 2.7", "MS-2.7-007", "MAP 5.1"], ["AML.T0061", "AML.M0015"]),

    # ── harness_impersonation_detector (NEW) ──
    "HARNESS_OUTPUT_SPOOF":          Mapping("ASI01", ["MEASURE 2.7", "MS-2.7-007"], ["AML.T0067", "AML.T0051"]),

    # ── exfiltration_detector (NEW) ──
    "EXFIL_MARKDOWN_IMAGE":          Mapping("ASI03", ["MEASURE 2.7", "MEASURE 2.10"], ["AML.T0025", "AML.T0024"]),
    "EXFIL_MARKDOWN_LINK":           Mapping("ASI03", ["MEASURE 2.7", "MEASURE 2.10"], ["AML.T0025", "AML.T0024"]),
    "EXFIL_OUTBOUND_SEND":           Mapping("ASI03", ["MEASURE 2.7", "MEASURE 2.10"], ["AML.T0025"]),
    "EXFIL_URL_ASSEMBLY":            Mapping("ASI03", ["MEASURE 2.7", "MEASURE 2.10"], ["AML.T0025"]),

    # ── agentic_detector (NEW) ──
    "AGENTIC_SKIP_CONFIRMATION":     Mapping("ASI03", ["MAP 4.2", "MEASURE 2.7"], ["AML.T0053", "AML.M0029"]),
    "AGENTIC_AUTONOMOUS_ACTION":     Mapping("ASI02", ["MAP 4.2", "MEASURE 2.7"], ["AML.T0053", "AML.M0030"]),
    "AGENTIC_MEMORY_POISONING":      Mapping("ASI06", ["MEASURE 2.7", "MAP 5.1"], ["AML.T0070", "AML.M0031"]),
    "AGENTIC_TOOL_CHAINING":         Mapping("ASI02", ["MAP 4.2", "MEASURE 2.7"], ["AML.T0053", "AML.M0028"]),
}


def lookup(finding_type: Optional[str], owasp_id: Optional[str]) -> Optional[Mapping]:
    """Resolve the framework mapping for a finding.

    Prefers a type-specific entry, then falls back to the OWASP-id table.
    Returns None when nothing matches (rare — surfaces unmapped rules in tests).
    """
    if finding_type and finding_type in _BY_TYPE:
        return _BY_TYPE[finding_type]
    if owasp_id and owasp_id in _BY_OWASP:
        return _BY_OWASP[owasp_id]
    return None


def enrich(findings) -> list:
    """Back-fill asi_id / nist_rmf / atlas_ids on each finding in place.

    Runs after all detectors, before the report is written. Existing values
    are preserved — a detector may pre-declare its own mapping.
    """
    for f in findings:
        m = lookup(getattr(f, "type", None), getattr(f, "owasp_id", None))
        if not m:
            continue
        if not getattr(f, "asi_id", None) and m.asi_id:
            f.asi_id = m.asi_id
        if not getattr(f, "nist_rmf", None) and m.nist_rmf:
            f.nist_rmf = list(m.nist_rmf)
        if not getattr(f, "atlas_ids", None) and m.atlas_ids:
            f.atlas_ids = list(m.atlas_ids)
    return findings


# ── Chart-data helpers ───────────────────────────────────────────────────────
#
# These support the frontend charts shown in the security dashboard:
#   • MITRE ATLAS Coverage  — per-tactic security score (0-100)
#   • NIST AI RMF           — per-function score (GOVERN / MAP / MEASURE / MANAGE)
#   • OWASP Agentic Top 10  — per-item worst severity status
#
# Source for tactic assignments: MITRE ATLAS v5.6.0 · https://atlas.mitre.org
# ----------------------------------------------------------------------------

# ATLAS technique ID → tactic name.
# Only AML.T* technique IDs are included; AML.M* mitigations have no tactic.
_TECHNIQUE_TACTIC: Dict[str, str] = {
    # Initial Access — adversary gains a foothold through the skill/agent surface
    "AML.T0051":     "Initial Access",   # LLM Prompt Injection
    "AML.T0051.001": "Initial Access",   # LLM Prompt Injection (indirect)
    "AML.T0010":     "Initial Access",   # ML Supply Chain Compromise
    "AML.T0010.001": "Initial Access",   # ML Supply Chain Compromise (data)
    "AML.T0011.001": "Initial Access",   # Malicious Dependency (supply-chain)
    # Execution — adversary runs code or commands via the agent
    "AML.T0011":     "Execution",        # User Execution
    "AML.T0050":     "Execution",        # Command and Scripting Interpreter
    "AML.T0069":     "Execution",        # Excessive Agency execution
    # Privilege Escalation — agent granted more authority than intended
    "AML.T0053":     "Privilege Escalation",  # AI Agent Tool Invocation / abuse
    # Persistence — injected behaviour survives across sessions
    "AML.T0048":     "Persistence",      # Backdoor ML Model
    "AML.T0061":     "Persistence",      # LLM Prompt Self-Replication
    # Defense Evasion — hiding malicious content from detectors / safety layers
    "AML.T0029":     "Defense Evasion",  # Functionality Circumvention
    "AML.T0054":     "Defense Evasion",  # LLM Jailbreak
    "AML.T0067":     "Defense Evasion",  # Trusted Output Components Manipulation
    "AML.T0068":     "Defense Evasion",  # LLM Steganography / Unicode smuggling
    # Credential Access — stealing secrets or tokens
    "AML.T0055":     "Credential Access",  # Unsecured Credentials
    # Collection — gathering data for later exfiltration
    "AML.T0070":     "Collection",       # LLM RAG / Memory Poisoning
    # Exfiltration — data leaving the trust boundary
    "AML.T0024":     "Exfiltration",     # Exfiltration via AI Inference API
    "AML.T0025":     "Exfiltration",     # Exfiltration via Cyber Means
    "AML.T0056":     "Exfiltration",     # Exfiltration via Malware Payload
    "AML.T0057":     "Exfiltration",     # Exfiltration via ML Inference API
    # Impact — disruption or corruption of data / model behaviour
    "AML.T0020":     "Impact",           # Poison Training Data
    "AML.T0066":     "Impact",           # Availability Attack
}

# Severity → score-deduction points (used by compute_chart_data).
_SEV_PENALTY: Dict[str, int] = {
    "critical": 20, "high": 12, "medium": 5, "low": 2, "info": 0,
}
_SEV_RANK: Dict[str, int] = {
    "critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0,
}
_RANK_LABEL: Dict[int, str] = {
    4: "CRITICAL", 3: "HIGH", 2: "MEDIUM", 1: "LOW", 0: "INFO",
}


def tactic_from_atlas_ids(atlas_ids: List[str]) -> Optional[str]:
    """Return the ATLAS tactic name for the first matching technique in *atlas_ids*.

    Skips mitigation IDs (AML.M*) — they belong to no tactic.
    """
    for aid in (atlas_ids or []):
        if aid.startswith("AML.T"):
            tactic = _TECHNIQUE_TACTIC.get(aid)
            if tactic:
                return tactic
    return None


def nist_function_from_controls(controls: List[str]) -> Optional[str]:
    """Derive the top-level NIST AI RMF function from a list of subcategory IDs.

    Subcategory prefix  →  top-level function
    GOVERN / GV-        →  "GOVERN"
    MAP                 →  "MAP"
    MEASURE / MS-       →  "MEASURE"
    MANAGE / MG-        →  "MANAGE"
    """
    _PREFIX_FN = (
        ("GOVERN", "GOVERN"), ("GV-",    "GOVERN"),
        ("MAP",    "MAP"),
        ("MEASURE","MEASURE"), ("MS-",   "MEASURE"),
        ("MANAGE", "MANAGE"),  ("MG-",   "MANAGE"),
    )
    for ctrl in (controls or []):
        word = ctrl.strip().upper()
        for prefix, fn in _PREFIX_FN:
            if word.startswith(prefix):
                return fn
    return None
    


def compute_chart_data(findings) -> Dict[str, Any]:
    """Compute chart-ready aggregates from a list of ScanFinding objects.

    Reads the framework fields already carried on each ScanFinding:
      deny   → MITRE ATLAS technique IDs (List[str])
      url    → NIST AI RMF controls joined with " | "
      column → OWASP Agentic Top 10 ID (e.g. "ASI01")

    Returns
    -------
    {
      "atlas_tactic_scores":  {"Initial Access": 73, "Exfiltration": 59, ...},
      "nist_function_scores": {"GOVERN": 83, "MAP": 76, "MEASURE": 72, "MANAGE": 79},
      "owasp_agentic_status": {"ASI01": "CRITICAL", "ASI03": "HIGH", ...},
    }

    Score formula: max(0, 100 - sum(severity_penalty per finding in that bucket)).
    Tactics / functions with no findings are omitted (frontend treats them as N/A).
    """
    tactic_sevs:  Dict[str, List[str]] = {}
    nist_fn_sevs: Dict[str, List[str]] = {}
    asi_worst:    Dict[str, int]        = {}

    for f in findings:
        sev = (
            f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        ).lower()

        # ATLAS tactic — derived from the atlas_ids in the deny field
        atlas_ids = list(getattr(f, "deny", None) or [])
        tactic = tactic_from_atlas_ids(atlas_ids)
        if tactic:
            tactic_sevs.setdefault(tactic, []).append(sev)

        # NIST function — derived from the joined controls in the url field
        nist_str = getattr(f, "url", None) or ""
        controls = [c.strip() for c in nist_str.split("|") if c.strip()]
        nist_fn  = nist_function_from_controls(controls)
        if nist_fn:
            nist_fn_sevs.setdefault(nist_fn, []).append(sev)

        # OWASP Agentic worst-severity — from the column field (asi_id)
        asi_id = getattr(f, "column", None)
        if asi_id:
            rank = _SEV_RANK.get(sev, 0)
            if rank > asi_worst.get(asi_id, -1):
                asi_worst[asi_id] = rank

    def _score(sevs: List[str]) -> int:
        return max(0, 100 - sum(_SEV_PENALTY.get(s, 0) for s in sevs))

    return {
        "atlas_tactic_scores": {
            t: _score(sevs) for t, sevs in sorted(tactic_sevs.items())
        },
        "nist_function_scores": {
            fn: _score(sevs) for fn, sevs in sorted(nist_fn_sevs.items())
        },
        "owasp_agentic_status": {
            asi: _RANK_LABEL.get(rank, "INFO")
            for asi, rank in sorted(asi_worst.items())
        },
    }
