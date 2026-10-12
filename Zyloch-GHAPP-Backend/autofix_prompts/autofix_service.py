from __future__ import annotations

import json
import logging
import os
import functools
import hashlib
import threading
import time
from pathlib import Path
from typing import Any, Dict

import requests


logger = logging.getLogger("autofix")
logger.setLevel(logging.INFO)
_PROMPT_PATHS = {
    "default": Path(__file__).with_name("autofix_remediation_prompt.md"),
    "sbom": Path(__file__).with_name("autofix_remediation_sbom_prompt.md"),
    "cis": Path(__file__).with_name("autofix_remediation_cis_prompt.md"),
}

_CIS_SCANNER_TYPES = {"cis-agent", "cis_agent", "cis"}
_CACHE_LOCK = threading.Lock()
_AUTOFIX_CACHE: Dict[str, tuple[float, Dict[str, Any]]] = {}
_INFLIGHT: Dict[str, threading.Event] = {}
_DEFAULT_CACHE_TTL = 3600
_DEFAULT_MAX_TOKENS = 8000


@functools.lru_cache(maxsize=2)
def _load_prompt(prompt_name: str = "default") -> str:
    prompt_path = _PROMPT_PATHS.get(prompt_name, _PROMPT_PATHS["default"])
    try:
        return prompt_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise RuntimeError(f"Autofix remediation prompt is unavailable: {prompt_name}") from exc


def _build_sbom_payload(finding: Dict[str, Any], code_block: str) -> Dict[str, Any]:
    """
    Shapes a single SBOM finding into the {code_block, finding} structure
    autofix_remediation_sbom_prompt.md's INPUT FORMAT expects, rather than the
    generic {violation, code_block} shape the default IaC prompt uses.
    CveAutofixActions only ever requests one CVE at a time, so `vulnerabilities`
    is a one-item list — the prompt still treats it as an array in case a
    caller ever supplies more than one CVE for the same package.
    """
    sbom = finding.get("sbom_context") or {}
    severity = str(finding.get("severity") or "").upper() or None
    cvss = sbom.get("cvss")
    kev = bool(sbom.get("kev"))
    return {
        "code_block": code_block,
        "finding": {
            "package": sbom.get("package"),
            "version": sbom.get("version"),
            "ecosystem": sbom.get("ecosystem"),
            "source_file": finding.get("file"),
            "max_severity": severity,
            "max_cvss": cvss,
            "vulnerabilities": [{
                "cve_id": sbom.get("cve"),
                "source": None,
                "severity": severity,
                "cvss_score": cvss,
                "epss_score": sbom.get("epss"),
                "epss_percentile": None,
                "epss_label": None,
                "risk_priority": None,
                "reachability": sbom.get("reachability"),
                "fix_version": sbom.get("patched"),
                "vex_status": None,
                "description": finding.get("description"),
                "published": None,
                "kev": kev,
                "kev_date_added": None,
                "kev_ransomware": None,
            }],
        },
    }


def _prompt_version(prompt: str) -> str:
    return hashlib.sha256(prompt.encode("utf-8")).hexdigest()[:16]


def _cache_key(
    finding: Dict[str, Any], model: str, prompt: str, tenant_id: str | None = None
) -> str:
    payload = {
        "prompt_version": _prompt_version(prompt),
        "model": model,
        "policy_code": finding.get("policy_code"),
        "policy_name": finding.get("policy_name"),
        "description": str(finding.get("description") or "").strip(),
        "severity": finding.get("severity"),
        "file": finding.get("file"),
        "line": finding.get("line"),
        "scanner_type": finding.get("scanner_type"),
        "code_block": str(finding.get("code_block") or "").strip(),
        "sbom_context": finding.get("sbom_context"),
        "tenant_id": str(tenant_id) if tenant_id else None,
    }
    serialized = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def _cache_ttl() -> int:
    try:
        return max(0, int(os.getenv("AUTOFIX_CACHE_TTL_SECONDS", str(_DEFAULT_CACHE_TTL))))
    except ValueError:
        return _DEFAULT_CACHE_TTL


def _get_cached(key: str) -> Dict[str, Any] | None:
    with _CACHE_LOCK:
        cached = _AUTOFIX_CACHE.get(key)
        if not cached:
            return None
        created_at, result = cached
        if time.monotonic() - created_at >= _cache_ttl():
            _AUTOFIX_CACHE.pop(key, None)
            return None
        return {**result, "cache_hit": True}


def _store_cached(key: str, result: Dict[str, Any]) -> None:
    with _CACHE_LOCK:
        _AUTOFIX_CACHE[key] = (time.monotonic(), result)
        max_entries = max(1, int(os.getenv("AUTOFIX_CACHE_MAX_ENTRIES", "512")))
        while len(_AUTOFIX_CACHE) > max_entries:
            oldest_key = min(_AUTOFIX_CACHE, key=lambda item: _AUTOFIX_CACHE[item][0])
            _AUTOFIX_CACHE.pop(oldest_key, None)


def _claim_request(key: str) -> tuple[threading.Event, bool]:
    with _CACHE_LOCK:
        event = _INFLIGHT.get(key)
        if event:
            return event, False
        event = threading.Event()
        _INFLIGHT[key] = event
        return event, True


def _release_request(key: str, event: threading.Event) -> None:
    with _CACHE_LOCK:
        if _INFLIGHT.get(key) is event:
            _INFLIGHT.pop(key, None)
            event.set()


def _gateway_client():
    base_url = os.getenv("LITELLM_BASE_URL", "").strip()
    api_key = os.getenv("LITELLM_API_KEY", "").strip()
    if not base_url or not api_key:
        raise RuntimeError("LITELLM_BASE_URL and LITELLM_API_KEY must be configured")

    return base_url.rstrip("/"), api_key


def generate_autofix(
    finding: Dict[str, Any],
    force_refresh: bool = False,
    tenant_id: str | None = None,
) -> Dict[str, Any]:
    """Generate a reviewed remediation proposal using the scanner-specific prompt."""
    code_block = str(finding.get("code_block") or "").strip()
    if not code_block:
        raise ValueError("A code_block is required to generate an autofix")

    model = os.getenv("AUTOFIX_MODEL", "gpt-5.4-mini").strip()
    logger.info("Autofix request model=%s policy_code=%s file=%s line=%s", model, finding.get("policy_code"), finding.get("file"), finding.get("line"))
    print(f"Autofix request model={model} policy_code={finding.get('policy_code')} file={finding.get('file')} line={finding.get('line')}")
    scanner_type_lower = str(finding.get("scanner_type") or "").lower()
    if scanner_type_lower == "sbom":
        prompt_name = "sbom"
    elif scanner_type_lower in _CIS_SCANNER_TYPES:
        prompt_name = "cis"
    else:
        prompt_name = "default"
    prompt = _load_prompt(prompt_name)
    key = _cache_key(finding, model, prompt, tenant_id)
    if not force_refresh:
        cached = _get_cached(key)
        if cached:
            logger.info("Autofix cache hit model=%s key=%s", model, key[:12])
            print(f"Autofix cache hit model={model} key={key[:12]}")
            return cached

    event, is_owner = _claim_request(key)
    if not is_owner:
        wait_seconds = max(1, int(os.getenv("AUTOFIX_CACHE_WAIT_SECONDS", "180")))
        event.wait(wait_seconds)
        cached = _get_cached(key)
        if cached:
            logger.info("Autofix coalesced request model=%s key=%s", model, key[:12])
            print(f"Autofix coalesced request model={model} key={key[:12]}")
            return cached
        raise RuntimeError("A matching autofix request did not complete in time")

    started_at = time.perf_counter()
    try:
        base_url, api_key = _gateway_client()
        logger.info("Autofix request to LiteLLM using base_url=%s model=%s key=%s", base_url, model, key[:12])
        print(f"Autofix request to LiteLLM using base_url={base_url} model={model} key={key[:12]}")
        if prompt_name == "sbom":
            user_payload = _build_sbom_payload(finding, code_block)
        else:
            user_payload = {
                "violation": {
                    "policy_code": finding.get("policy_code"),
                    "policy_name": finding.get("policy_name"),
                    "description": finding.get("description"),
                    "severity": finding.get("severity"),
                    "file": finding.get("file"),
                    "line": finding.get("line"),
                    "scanner_type": finding.get("scanner_type"),
                },
                "code_block": code_block,
            }
            if finding.get("sbom_context") is not None:
                user_payload["sbom"] = finding["sbom_context"]
        logger.info("Autofix request payload %s", json.dumps(user_payload, ensure_ascii=False))
        print(f"Autofix request payload {json.dumps(user_payload, ensure_ascii=False)}")

        endpoint = base_url if base_url.endswith("/v1") else f"{base_url}/v1"
        logger.info("endpoint=%s", endpoint)
        print(f"endpoint={endpoint}")
        response = requests.post(
            f"{endpoint}/chat/completions",
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json={
                "model": model,
                "max_tokens": int(os.getenv("AUTOFIX_MAX_TOKENS", str(_DEFAULT_MAX_TOKENS))),
                "temperature": 0,
                "prompt_cache_key": f"zyloch-autofix-{_prompt_version(prompt)}",
                "messages": [
                    {"role": "system", "content": prompt},
                    {
                        "role": "user",
                        "content": (
                            (
                                "Run the full analysis on this single dependency finding. "
                                "Use only the supplied finding and code block; do not invent "
                                "surrounding dependencies or additional CVEs. Return the remediation "
                                "document as markdown only.\n\n"
                                if prompt_name == "sbom" else
                                "Generate the complete autofix remediation document for this single "
                                "violation. Use only the supplied finding and code block; do not "
                                "invent surrounding configuration. Return the remediation document "
                                "as markdown only.\n\n"
                            )
                            + "```json\n"
                            + json.dumps(user_payload, ensure_ascii=False)
                            + "\n```"
                        ),
                    },
                ],
            },
            timeout=(10, int(os.getenv("AUTOFIX_TIMEOUT_SECONDS", "180"))),
        )
        logger.info(f"Autofix response status {response.status_code}")
        print(f"Autofix response status {response.status_code}")
        response.raise_for_status()
        response_data = response.json()
        logger.info(f"response data {response_data}")
        print(f"response data {response_data}")

        choices = response_data.get("choices") or []
        message = choices[0].get("message") if choices else None
        content = message.get("content") if isinstance(message, dict) else None
        if not content or not content.strip():
            raise RuntimeError("LiteLLM returned an empty autofix response")

        result = {
            "model": model,
            "content": content.strip(),
            "cache_hit": False,
            "latency_ms": round((time.perf_counter() - started_at) * 1000),
        }
        _store_cached(key, result)
        usage = response_data.get("usage") or {}
        logger.info(
            "Autofix generated model=%s key=%s latency_ms=%s prompt_tokens=%s completion_tokens=%s",
            model,
            key[:12],
            result["latency_ms"],
            usage.get("prompt_tokens"),
            usage.get("completion_tokens"),
        )
        return result
    finally:
        _release_request(key, event)


def generate_sbom_autofix(
    finding: Dict[str, Any],
    force_refresh: bool = False,
    tenant_id: str | None = None,
) -> Dict[str, Any]:
    """Generate an SBOM remediation proposal with the SBOM-specific prompt."""
    sbom_finding = {**finding, "scanner_type": "sbom"}
    return generate_autofix(sbom_finding, force_refresh, tenant_id)
