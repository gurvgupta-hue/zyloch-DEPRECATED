"""Harness / trusted-output impersonation detector.

Catches skill content that forges the framing of TRUSTED runtime components —
fake tool-result blocks, fake system/assistant turns, forged function-call
results, fake "verified"/safety banners — so injected text looks like it
came from the agent harness rather than from an untrusted skill file.

This is distinct from plain prompt injection (`ignore previous…`): here the
attack impersonates the *structure* the model trusts, which is exactly how
indirect injection escalates into accepted instructions.

Maps to:
  - MITRE ATLAS  AML.T0067  LLM Trusted Output Components Manipulation (Defense Evasion)
  - OWASP Agentic ASI01     Agent Goal Hijack
  - NIST AI RMF  MEASURE 2.7 / MS-2.7-007

Note: the OWASP detector already flags a bare `[system]:` tag. This detector
covers the broader family of harness-control tokens used by modern agent
runtimes (XML-style tool/result/function tags, chat-turn role headers, and
forged trust banners) that a plain role-tag regex misses.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Pattern

from scanner_core.helpers.models import HarmCategory, Layer1Finding, Severity


@dataclass(frozen=True)
class _Rule:
    pattern: Pattern[str]
    severity: Severity
    desc: str


def _re(s: str) -> Pattern[str]:
    return re.compile(s, re.IGNORECASE)


_RULES: List[_Rule] = [
    # Forged XML/markup tool-runtime tags impersonating harness internals.
    _Rule(_re(r"</?\s*(tool_result|tool_use|function_results?|function_call|"
              r"system|assistant|antml:|thinking|tool_output|observation)\b[^>]*>"),
          "HIGH", "Forged runtime/control tag impersonating the agent harness"),
    # Chat-turn role headers used to spoof a conversation boundary.
    _Rule(_re(r"(?m)^\s*(system|assistant|tool|developer)\s*[:>]\s*\S"),
          "HIGH", "Spoofed chat-turn role header (fake system/assistant/tool turn)"),
    # Fake tool/function OUTPUT framing.
    _Rule(_re(r"\b(tool|function|command|shell)\s+(output|result|response)\s*[:=]\s*\S",),
          "MEDIUM", "Forged tool/function output framing"),
    # Forged trust/verification banners that grant injected text authority.
    _Rule(_re(r"\b(verified|approved|authorized|trusted|official)\s+by\s+"
              r"(the\s+)?(system|anthropic|claude|administrator|security\s+team)\b"),
          "MEDIUM", "Forged trust/verification banner asserting harness authority"),
    # "This is a system message / an official system instruction from the platform"
    _Rule(_re(r"\bthis\s+is\s+(an?\s+)?(official|trusted|system|verified|platform)\b"
              r"[\w\s-]{0,20}?\b(message|instruction|directive|notice)\b"),
          "MEDIUM", "Claim that untrusted content is an official/system message"),
]


def detect(text: str) -> List[Layer1Finding]:
    findings: List[Layer1Finding] = []
    if not text:
        return findings

    seen: set[str] = set()
    for rule in _RULES:
        m = rule.pattern.search(text)
        if not m:
            continue
        # Dedup identical desc (the role-header and tag rules can overlap).
        if rule.desc in seen:
            continue
        seen.add(rule.desc)
        line = text.count("\n", 0, m.start()) + 1
        snippet_start = max(0, m.start() - 20)
        snippet_end = min(len(text), m.end() + 30)
        findings.append(Layer1Finding(
            detector="harness_impersonation_detector",
            type="HARNESS_OUTPUT_SPOOF",
            owasp_id="LLM01",
            severity=rule.severity,
            line=line,
            matched_snippet=text[snippet_start:snippet_end].strip()[:160],
            harm_category="MANIPULATION",
            recommended_action=f"{rule.desc}. Remove forged trusted-output framing from the skill body.",
        ))

    return findings
