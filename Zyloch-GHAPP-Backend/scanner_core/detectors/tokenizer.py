"""Tokenizer-aware analysis.

Catches payloads that look benign in raw text but merge into injection
strings once tokenized (e.g. "ign|ore" rejoining as "ignore"). Uses
tiktoken with cl100k_base when available; falls back to a character-level
sliding window when not.
"""
from __future__ import annotations

import re
from typing import List

from scanner_core.helpers.models import Layer1Finding

try:
    import tiktoken  # type: ignore
    _ENC = tiktoken.get_encoding("cl100k_base")
except Exception:  # pragma: no cover - dependency optional
    _ENC = None


# Injection patterns to look for in the merged token stream.
INJECTION_PATTERNS = [
    re.compile(r"ignore\s+(previous|prior|all|your)\s+instructions", re.IGNORECASE),
    re.compile(r"disregard\s+(previous|prior|all|your)\s+instructions", re.IGNORECASE),
    re.compile(r"forget\s+your\s+(instructions|rules|guidelines)", re.IGNORECASE),
    re.compile(r"you\s+are\s+now\s+(?!a\s+helpful)", re.IGNORECASE),
    re.compile(r"new\s+instructions\s*[:>]", re.IGNORECASE),
    re.compile(r"\[\s*system\s*\]\s*:", re.IGNORECASE),
    re.compile(r"reveal\s+your\s+system\s+prompt", re.IGNORECASE),
]


def _matches(s: str):
    for p in INJECTION_PATTERNS:
        m = p.search(s)
        if m:
            return p.pattern, m.group(0)
    return None


def detect(text: str) -> List[Layer1Finding]:
    findings: List[Layer1Finding] = []
    if not text:
        return findings

    if _ENC is not None:
        try:
            token_ids = _ENC.encode(text)
        except Exception:
            token_ids = []
        # Sliding window of merged tokens.
        for start in range(0, max(1, len(token_ids) - 4), 4):
            window = token_ids[start : start + 24]
            try:
                decoded = _ENC.decode(window)
            except Exception:
                continue
            hit = _matches(decoded)
            if hit:
                pattern, matched = hit
                # Only flag if the same string was NOT present verbatim in raw text
                # (otherwise the OWASP detector would catch it on its own).
                if matched.lower() not in text.lower():
                    findings.append(
                        Layer1Finding(
                            detector="tokenizer",
                            type="TOKEN_MERGE_INJECTION",
                            owasp_id="LLM01",
                            severity="HIGH",
                            matched_snippet=matched,
                            harm_category="MANIPULATION",
                            recommended_action=(
                                "Investigate text region whose tokenization merges into an injection string"
                            ),
                        )
                    )
                    break
    else:
        # Character-level fallback: strip all non-alphanum and re-scan.
        squeezed = re.sub(r"[^A-Za-z0-9 ]+", "", text)
        if squeezed != text:
            hit = _matches(squeezed)
            if hit and hit[1].lower() not in text.lower():
                findings.append(
                    Layer1Finding(
                        detector="tokenizer",
                        type="TOKEN_MERGE_INJECTION",
                        owasp_id="LLM01",
                        severity="HIGH",
                        matched_snippet=hit[1],
                        harm_category="MANIPULATION",
                        recommended_action="Suspicious punctuation breaks an injection string",
                    )
                )

    return findings
