from __future__ import annotations

import functools
import json
import logging
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Dict, List, Tuple

import requests

log = logging.getLogger("autofix")

# ---------------------------------------------------------------------------
# SBOM finding LLM enrichment/validation
#
# Runs only for SBOM-only scan requests (see main.py). For every CVE/GHSA
# finding attached to a scanned dependency, asks the LLM gateway to apply the
# full analysis workflow from autofix_prompts/sbom_enrichment_prompt.txt:
# validate whether the finding genuinely applies (or is a scanner false
# positive / not-affected), then classify reachability, exploitability, and
# production-vs-dev context.
#
# Findings the LLM decides are FALSE_POSITIVE or NOT_AFFECTED are dropped
# before the scan result is persisted, so they never reach the UI or the
# database. The remaining (validated) findings are annotated in place with
# the AI decision/reachability/exploitability/confidence, and rolled up into
# four counters — total, possibly-reachable, production, and fixable CVEs —
# that get stored alongside the scan and returned in the API response.
#
# Fails safe: any gateway/parse error leaves the dependencies untouched
# rather than risk silently deleting real vulnerabilities.
# ---------------------------------------------------------------------------

_PROMPT_PATH = Path(__file__).with_name("sbom_enrichment_prompt.txt")

_STRUCTURED_OUTPUT_INSTRUCTIONS = """

INPUT FIELD REFERENCE
Each finding you receive is one JSON object with these fields — use every one of them in
the corresponding analysis stage above; do not ignore a field because the workflow above
describes it in prose rather than by key name:
  package, version, ecosystem, source_file, dependency_type — stage 1 (package identity)
    and the DOCUMENTATION/DEVELOPMENT DEPENDENCIES rule (production_context judgment).
  cve_id, description, published — stage 3 (deep vulnerability research context).
  cvss_score, cvss_vector, cwe_ids — stage 4 (actual impact / weakness class; use cwe_ids
    to judge RCE/deserialization/injection classes as instructed).
  reachability — stage 5 (scanner-provided signal only, not proof — SPECIAL RULE applies).
  cvss_vector, risk_priority, risk_score — stage 6 (exploitability: attack vector,
    complexity, privileges required, from the CVSS vector string).
  epss_score, epss_percentile, epss_label, kev, kev_date_added, kev_ransomware — stage 7
    (EPSS is a probability signal, not proof; KEV, especially with kev_ransomware=true, is
    a strong prioritization signal regardless of EPSS).
  fix_version, vex_status — stage 2 (version-range validation) and false-positive
    investigation (stage 8): a VEX status of not_affected/fixed is strong FALSE_POSITIVE or
    NOT_AFFECTED evidence.
  oss_risk — stage 11 (supply-chain / maintainer trust signal).
Never let a missing/null field block a decision on the fields that are present; set
confidence lower and reachability/exploitability to UNKNOWN only for the specific
dimension the missing data affects.

STRUCTURED OUTPUT OVERRIDE
Ignore the "OUTPUT FORMAT" section above (the executive-summary/markdown-table format) —
instead, apply the exact same analysis workflow, risk-decision taxonomy, reachability and
exploitability classifications, and false-positive/production-dependency judgment to every
finding in the JSON array you receive, and return ONLY the structured JSON object matching
the provided tool schema. No prose outside it.
"""


@functools.lru_cache(maxsize=1)
def _load_system_prompt() -> str:
    try:
        base_prompt = _PROMPT_PATH.read_text(encoding="utf-8")
    except OSError as exc:
        raise RuntimeError(f"SBOM enrichment prompt is unavailable: {_PROMPT_PATH}") from exc
    return base_prompt + _STRUCTURED_OUTPUT_INSTRUCTIONS


ENRICHMENT_SCHEMA = {
    "name": "sbom_cve_enrichment",
    "strict": True,
    "schema": {
        "type": "object",
        "additionalProperties": False,
        "required": ["verdicts"],
        "properties": {
            "verdicts": {
                "type": "array",
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": [
                        "id", "decision", "reachability", "exploitability",
                        "production_context", "confidence", "reason",
                    ],
                    "properties": {
                        "id": {"type": "string"},
                        "decision": {
                            "type": "string",
                            "enum": [
                                "CRITICAL", "HIGH", "MEDIUM", "LOW", "MONITOR",
                                "NOT_AFFECTED", "FALSE_POSITIVE", "INCONCLUSIVE",
                            ],
                        },
                        "reachability": {
                            "type": "string",
                            "enum": ["REACHABLE", "POTENTIALLY_REACHABLE", "NOT_REACHABLE", "UNKNOWN"],
                        },
                        "exploitability": {
                            "type": "string",
                            "enum": ["VERY_LOW", "LOW", "MODERATE", "HIGH", "VERY_HIGH", "UNKNOWN"],
                        },
                        "production_context": {
                            "type": "string",
                            "enum": ["PRODUCTION", "NON_PRODUCTION", "UNKNOWN"],
                        },
                        "confidence": {"type": "integer", "minimum": 0, "maximum": 100},
                        "reason": {"type": "string"},
                    },
                },
            },
        },
    },
}

# Decisions that mean "this finding does not apply here" — dropped from the
# persisted result entirely, same as before.
_REMOVED_DECISIONS = {"FALSE_POSITIVE", "NOT_AFFECTED"}
_REACHABLE_STATES = {"REACHABLE", "POTENTIALLY_REACHABLE"}

_BATCH_SIZE = int(os.getenv("SBOM_FP_VALIDATION_BATCH_SIZE", "25"))


def _gateway_client() -> Tuple[str, str]:
    base_url = os.getenv("LITELLM_BASE_URL", "").strip()
    api_key = os.getenv("LITELLM_API_KEY", "").strip()
    if not base_url or not api_key:
        raise RuntimeError("LITELLM_BASE_URL and LITELLM_API_KEY must be configured")
    return base_url.rstrip("/"), api_key


def _collect_items(dependencies: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Flatten every (dependency, vulnerability) pair into one LLM-ready item."""
    items: List[Dict[str, Any]] = []
    for dep_idx, dep in enumerate(dependencies or []):
        vulns = dep.get("vulnerabilities") or []
        for vuln_idx, vuln in enumerate(vulns):
            items.append({
                "id": f"{dep_idx}:{vuln_idx}",
                "package": dep.get("name"),
                "version": dep.get("version"),
                "ecosystem": dep.get("ecosystem"),
                "source_file": dep.get("source_file"),
                "dependency_type": dep.get("dependency_type"),
                "cve_id": vuln.get("cve_id"),
                "severity": vuln.get("severity"),
                "cvss_score": vuln.get("cvss_score"),
                "cvss_vector": vuln.get("cvss_vector"),
                "cwe_ids": vuln.get("cwe_ids"),
                "fix_version": vuln.get("fix_version"),
                "description": vuln.get("description"),
                "published": vuln.get("published"),
                "reachability": vuln.get("reachability"),
                "risk_priority": vuln.get("risk_priority"),
                "risk_score": vuln.get("risk_score"),
                "oss_risk": vuln.get("oss_risk"),
                "epss_score": vuln.get("epss_score"),
                "epss_percentile": vuln.get("epss_percentile"),
                "epss_label": vuln.get("epss_label"),
                "kev": vuln.get("kev"),
                "kev_date_added": vuln.get("kev_date_added"),
                "kev_ransomware": vuln.get("kev_ransomware"),
                "vex_status": vuln.get("vex_status"),
            })
    return items


def _call_gateway(items: List[Dict[str, Any]], model: str) -> Dict[str, Dict[str, Any]]:
    """Returns {id: verdict_dict} for the given batch of items."""
    base_url, api_key = _gateway_client()
    system_prompt = _load_system_prompt()
    user_msg = (
        "Apply the analysis workflow to every SBOM vulnerability finding below and "
        "return only the structured JSON object.\n\n"
        "```json\n" + json.dumps(items, ensure_ascii=False, separators=(",", ":")) + "\n```"
    )

    endpoint = base_url if base_url.endswith("/v1") else f"{base_url}/v1"
    response = requests.post(
        f"{endpoint}/chat/completions",
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        json={
            "model": model,
            "max_tokens": int(os.getenv("SBOM_FP_VALIDATION_MAX_TOKENS", "8000")),
            "temperature": 0,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_msg},
            ],
            "tools": [{
                "type": "function",
                "function": {
                    "name": "sbom_cve_enrichment",
                    "description": "Return the SBOM CVE enrichment verdicts.",
                    "parameters": ENRICHMENT_SCHEMA["schema"],
                },
            }],
            "tool_choice": {"type": "function", "function": {"name": "sbom_cve_enrichment"}},
        },
        timeout=(10, int(os.getenv("SBOM_FP_VALIDATION_TIMEOUT_SECONDS", "90"))),
    )
    log.info("SBOM enrichment gateway response status %s", response.status_code)
    response.raise_for_status()
    response_data = response.json()

    choices = response_data.get("choices") or []
    message = choices[0].get("message") if choices else None
    tool_calls = message.get("tool_calls") if isinstance(message, dict) else None
    if not tool_calls:
        raise RuntimeError("No sbom_cve_enrichment tool call in gateway response")
    arguments = tool_calls[0].get("function", {}).get("arguments")
    if not arguments:
        raise RuntimeError("sbom_cve_enrichment tool call had no arguments")
    args = json.loads(arguments)

    verdicts: Dict[str, Dict[str, Any]] = {}
    for entry in args.get("verdicts", []):
        item_id = entry.get("id")
        if item_id and entry.get("decision"):
            verdicts[item_id] = entry
    return verdicts


def validate_sbom_dependencies(
    dependencies: List[Dict[str, Any]],
    model: str | None = None,
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """
    Runs LLM enrichment over every vulnerability attached to the given SBOM
    dependencies: validates true-positive vs false-positive/not-affected, and
    classifies reachability, exploitability, and production-vs-dev context.

    Findings judged FALSE_POSITIVE or NOT_AFFECTED are stripped out. Every
    surviving vulnerability is annotated in place with `ai_decision`,
    `ai_reachability`, `ai_exploitability`, `ai_production_context`,
    `ai_confidence`, and `ai_reason`.

    Returns (filtered_dependencies, stats), where stats includes:
      - total_cves: count of surviving (validated) CVE findings
      - possibly_reachable_cves: of those, REACHABLE or POTENTIALLY_REACHABLE
      - production_cves: of those, judged to affect a production dependency
      - fixable_cves: of those, with a known fix_version available
      - removed_false_positives: count dropped as FALSE_POSITIVE/NOT_AFFECTED
      - possibly_reachable_cve_ids / production_cve_ids / fixable_cve_ids: the
        {package, cve_id, reachability|production_context, ai_decision} identity of
        every CVE behind the corresponding count above, so "13 possibly reachable"
        can be pointed at the exact 13 CVEs rather than just a number.

    Fails safe per batch, not all-or-nothing: findings are processed in
    batches run concurrently, and a batch that errors/times out only affects
    the findings in that batch (they fall back to INCONCLUSIVE — kept,
    unenriched) rather than discarding every other batch's verdicts. Only
    when every batch fails does this behave like a full outage (all findings
    kept, `validated=False`). `stats["batches_failed"]`/`["batches_total"]`
    report how many batches actually succeeded.
    """
    stats = {
        "total_findings": 0,
        "total_cves": 0,
        "possibly_reachable_cves": 0,
        "production_cves": 0,
        "fixable_cves": 0,
        "removed_false_positives": 0,
        "possibly_reachable_cve_ids": [],
        "production_cve_ids": [],
        "fixable_cve_ids": [],
        "batches_total": 0,
        "batches_failed": 0,
        "validated": False,
        "error": None,
    }
    items = _collect_items(dependencies)
    stats["total_findings"] = len(items)
    if not items:
        stats["validated"] = True
        return dependencies, stats

    resolved_model = model or os.getenv("SBOM_FP_VALIDATION_MODEL", "gpt-5.4-mini").strip()
    batches = [items[start:start + _BATCH_SIZE] for start in range(0, len(items), _BATCH_SIZE)]
    max_workers = min(len(batches), int(os.getenv("SBOM_FP_VALIDATION_MAX_WORKERS", "12")))
    verdicts: Dict[str, Dict[str, Any]] = {}
    batches_failed = 0

    # Batches are independent, so run them concurrently — sequential calls
    # would otherwise add batch_count * per_call_timeout to the scan's total
    # duration and risk timing out whatever is waiting on the scan to finish
    # (e.g. the UI refreshing scan status). Each batch is also isolated: one
    # slow/timed-out batch must never discard the verdicts already collected
    # from every OTHER successful batch — a large scan (1000+ findings, dozens
    # of batches) is expected to have the occasional batch fail, and losing
    # everything because of it defeats enrichment for exactly the scans that
    # need it most.
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        future_to_batch = {pool.submit(_call_gateway, batch, resolved_model): batch for batch in batches}
        for future in as_completed(future_to_batch):
            try:
                verdicts.update(future.result())
            except Exception as exc:  # noqa: BLE001 - one bad batch must not sink the rest
                batches_failed += 1
                log.warning(
                    "SBOM enrichment batch failed (%d items) — those findings fall back to "
                    "INCONCLUSIVE/unenriched, other batches are unaffected: %s",
                    len(future_to_batch[future]), exc,
                )

    stats["batches_total"] = len(batches)
    stats["batches_failed"] = batches_failed
    if batches_failed:
        stats["error"] = f"{batches_failed}/{len(batches)} enrichment batches failed"
    # "validated" means at least some enrichment actually happened. Findings in
    # failed batches simply have no verdict, which the per-finding loop below
    # already treats as INCONCLUSIVE (kept, unenriched) rather than dropped —
    # so a partial failure degrades gracefully instead of discarding everything.
    stats["validated"] = batches_failed < len(batches)

    filtered_dependencies: List[Dict[str, Any]] = []
    for dep_idx, dep in enumerate(dependencies):
        vulns = dep.get("vulnerabilities") or []
        kept_vulns = []
        for vuln_idx, vuln in enumerate(vulns):
            item_id = f"{dep_idx}:{vuln_idx}"
            verdict = verdicts.get(item_id)
            decision = (verdict or {}).get("decision", "INCONCLUSIVE")

            if decision in _REMOVED_DECISIONS:
                stats["removed_false_positives"] += 1
                log.info(
                    "SBOM finding removed by LLM (%s): package=%s cve=%s",
                    decision, dep.get("name"), vuln.get("cve_id"),
                )
                continue

            reachability = (verdict or {}).get("reachability", "UNKNOWN")
            production_context = (verdict or {}).get("production_context", "UNKNOWN")
            enriched_vuln = {
                **vuln,
                "ai_decision": decision,
                "ai_reachability": reachability,
                "ai_exploitability": (verdict or {}).get("exploitability", "UNKNOWN"),
                "ai_production_context": production_context,
                "ai_confidence": (verdict or {}).get("confidence"),
                "ai_reason": (verdict or {}).get("reason", ""),
            }
            kept_vulns.append(enriched_vuln)

            identity = {
                "package": dep.get("name"),
                "version": dep.get("version"),
                "cve_id": vuln.get("cve_id"),
                "ai_decision": decision,
            }

            stats["total_cves"] += 1
            if reachability in _REACHABLE_STATES:
                stats["possibly_reachable_cves"] += 1
                stats["possibly_reachable_cve_ids"].append({**identity, "reachability": reachability})
            if production_context == "PRODUCTION":
                stats["production_cves"] += 1
                stats["production_cve_ids"].append({**identity, "production_context": production_context})
            if str(vuln.get("fix_version") or "").strip():
                stats["fixable_cves"] += 1
                stats["fixable_cve_ids"].append({**identity, "fix_version": vuln.get("fix_version")})

        filtered_dependencies.append({**dep, "vulnerabilities": kept_vulns})

    return filtered_dependencies, stats
