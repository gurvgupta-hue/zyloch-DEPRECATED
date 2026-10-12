"""Reveal hidden payloads.

Operates on raw text (for unicode-encoded payloads) and on existing
Layer 1 findings (to enrich them with decoded_payload + harm_category
when a detector left those fields empty).
"""
from __future__ import annotations

import base64
import re
import urllib.parse
from typing import List, Optional

from scanner_core.helpers.models import HarmCategory, Layer1Finding

HARM_RULES = [
    ("EXFILTRATION", re.compile(
        r"\b(send|post|upload|exfiltrate|leak|fetch).{0,30}(http|https|url|endpoint|webhook|server)",
        re.IGNORECASE)),
    ("PRIVILEGE_ESCALATION", re.compile(
        r"\b(sudo|root|admin|grant|escalat|permission|chmod\s+777|all\s+permissions|\*\s*permission)",
        re.IGNORECASE)),
    ("JAILBREAK", re.compile(
        r"\b(DAN|do\s+anything\s+now|jailbreak|without\s+restrictions|no\s+limitations|developer\s+mode)",
        re.IGNORECASE)),
    ("SOCIAL_ENGINEERING", re.compile(
        r"\b(please\s+trust|i\s+am\s+your\s+(creator|owner|admin)|urgent|critical\s+update|i\s+promise|just\s+this\s+once)",
        re.IGNORECASE)),
    ("SUPPLY_CHAIN", re.compile(
        r"\b(load|import|require|include|fetch).{0,30}(from|@)\s*(https?://|github\.com|gist\.)",
        re.IGNORECASE)),
    ("MANIPULATION", re.compile(
        r"\b(ignore|disregard|forget|override|bypass).{0,30}(instructions|rules|guidelines|prompt|system)",
        re.IGNORECASE)),
]


def classify_harm(decoded: str) -> Optional[HarmCategory]:
    if not decoded:
        return None
    for cat, pattern in HARM_RULES:
        if pattern.search(decoded):
            return cat  # type: ignore[return-value]
    return None


def _decode_html_entities(s: str) -> str:
    def _num(m):
        try:
            return chr(int(m.group(1)))
        except (ValueError, OverflowError):
            return m.group(0)

    def _hex(m):
        try:
            return chr(int(m.group(1), 16))
        except (ValueError, OverflowError):
            return m.group(0)

    s = re.sub(r"&#(\d+);", _num, s)
    s = re.sub(r"&#x([0-9A-Fa-f]+);", _hex, s)
    return s


def _decode_base64(candidate: str) -> Optional[str]:
    if len(candidate) < 8 or len(candidate) % 4 != 0:
        return None
    if not re.fullmatch(r"[A-Za-z0-9+/=]+", candidate):
        return None
    try:
        decoded = base64.b64decode(candidate, validate=True).decode("utf-8", errors="strict")
    except Exception:
        return None
    if not any(c.isprintable() for c in decoded):
        return None
    return decoded


def _decode_url(s: str) -> str:
    if "%" not in s:
        return s
    try:
        return urllib.parse.unquote(s)
    except Exception:
        return s


def scan(text: str) -> List[Layer1Finding]:
    """Find embedded encoded payloads in raw text and decode them."""
    findings: List[Layer1Finding] = []

    # HTML numeric entities forming a hidden ASCII string.
    if re.search(r"&#x?[0-9A-Fa-f]+;.*&#x?[0-9A-Fa-f]+;", text):
        decoded = _decode_html_entities(text)
        if decoded != text:
            harm = classify_harm(decoded)
            if harm:
                findings.append(
                    Layer1Finding(
                        detector="payload_decoder",
                        type="HTML_ENTITY_PAYLOAD",
                        owasp_id="LLM01",
                        severity="HIGH",
                        decoded_payload=decoded[:500],
                        harm_category=harm,
                        recommended_action="Remove HTML-entity-encoded instruction payload",
                    )
                )

    # Base64-looking blobs of length >= 20.
    for m in re.finditer(r"[A-Za-z0-9+/=]{20,}", text):
        decoded = _decode_base64(m.group(0))
        if decoded:
            harm = classify_harm(decoded)
            if harm:
                findings.append(
                    Layer1Finding(
                        detector="payload_decoder",
                        type="BASE64_PAYLOAD",
                        owasp_id="LLM01",
                        severity="HIGH",
                        line=text.count("\n", 0, m.start()) + 1,
                        matched_snippet=m.group(0)[:60] + "...",
                        decoded_payload=decoded[:500],
                        harm_category=harm,
                        recommended_action="Remove base64-encoded instruction payload",
                    )
                )

    # URL-encoded payloads.
    if re.search(r"%[0-9A-Fa-f]{2}.*%[0-9A-Fa-f]{2}", text):
        decoded = _decode_url(text)
        if decoded != text:
            harm = classify_harm(decoded)
            if harm:
                findings.append(
                    Layer1Finding(
                        detector="payload_decoder",
                        type="URL_ENCODED_PAYLOAD",
                        owasp_id="LLM01",
                        severity="MEDIUM",
                        decoded_payload=decoded[:500],
                        harm_category=harm,
                        recommended_action="Remove URL-encoded instruction payload",
                    )
                )

    return findings


def enrich(findings: List[Layer1Finding]) -> List[Layer1Finding]:
    """Backfill harm_category on any finding that has a decoded payload but no category."""
    for f in findings:
        if f.decoded_payload and not f.harm_category:
            harm = classify_harm(f.decoded_payload)
            if harm:
                f.harm_category = harm
    return findings
