"""Agentic-behavior detector (OWASP Agentic Top 10).

The OWASP LLM Top 10 covers prompt-level attacks. The OWASP Agentic Top 10
(ASI01-ASI10) covers what a skill can make an AUTONOMOUS agent *do*: misuse
tools, escalate privilege, bypass the human-in-the-loop, and poison its own
persistent memory. This detector catches those directives in the skill body
itself (in addition to the frontmatter/config trust-elevation advisories the
other detectors already raise).

Maps to:
  - OWASP Agentic ASI02 Tool Misuse, ASI03 Identity & Privilege Abuse,
    ASI06 Memory & Context Poisoning
  - MITRE ATLAS AML.T0053 AI Agent Tool Invocation, AML.T0070 RAG Poisoning;
    mitigations M0028/M0029/M0030/M0031
  - NIST AI RMF MAP 4.2, MEASURE 2.7, MAP 5.1

Real-world grounding:
  - ATLAS AML.CS0038 — planted instructions for delayed automatic tool invocation
  - ATLAS AML.CS0040 — hacking ChatGPT memories via prompt injection
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
    harm: HarmCategory
    action: str


def _re(s: str) -> Pattern[str]:
    return re.compile(s, re.IGNORECASE)


_RULES: List[_Rule] = [
    # ── ASI03 — bypass human-in-the-loop / skip confirmation ───────────
    _Rule("AGENTIC_SKIP_CONFIRMATION", "HIGH",
          _re(r"\b(do\s*n[o']?t|never|without|skip|no\s+need\s+to|don'?t\s+bother)\b"
              r".{0,30}\b(ask|prompt|confirm|confirmation|approval|permission|check\s+with)\b"
              r".{0,25}\b(the\s+)?(user|human|operator|me|developer)\b"),
          "PRIVILEGE_ESCALATION",
          "Remove directive to bypass human confirmation before taking action (ASI03 / human-in-the-loop bypass)"),
    _Rule("AGENTIC_SKIP_CONFIRMATION", "HIGH",
          _re(r"\b(auto[\s-]?approve|automatically\s+(approve|accept|confirm)|"
              r"proceed\s+without\s+(asking|confirmation|permission|approval))\b"),
          "PRIVILEGE_ESCALATION",
          "Remove auto-approval directive that skips the approval prompt (ASI03)"),

    # ── ASI02 — autonomous / unconstrained action ──────────────────────
    _Rule("AGENTIC_AUTONOMOUS_ACTION", "MEDIUM",
          _re(r"\b(act\s+autonomously|on\s+your\s+own\s+initiative|"
              r"take\s+(any|whatever)\s+action(s)?\s+(necessary|needed|required)|"
              r"do\s+whatever\s+it\s+takes|without\s+(human\s+)?(oversight|supervision|review))\b"),
          "MANIPULATION",
          "Audit directive granting unconstrained autonomous action (ASI02 tool misuse)"),

    # ── ASI02 — tool chaining without review ───────────────────────────
    _Rule("AGENTIC_TOOL_CHAINING", "MEDIUM",
          _re(r"\b(chain|pipe|automatically\s+run|immediately\s+(run|invoke|execute|call))\b"
              r".{0,40}\b(tool|command|function|action|skill)s?\b"
              r".{0,40}\b(without|don'?t|no)\b.{0,20}\b(review|checking|verifying|confirm)\w*"),
          "PRIVILEGE_ESCALATION",
          "Audit directive chaining tool calls without reviewing intermediate output (ASI02)"),

    # ── ASI06 — persistent memory / context poisoning ──────────────────
    _Rule("AGENTIC_MEMORY_POISONING", "HIGH",
          _re(r"\b(remember|retain|keep|store|save|persist|memorize)\b"
              r".{0,40}\b(across|for\s+all|in\s+(future|every)|between|beyond\s+this)\b"
              r".{0,20}\b(session|conversation|chat|future|context)s?\b"),
          "MANIPULATION",
          "Remove persistent cross-session memory injection (ASI06 memory poisoning)"),
    _Rule("AGENTIC_MEMORY_POISONING", "HIGH",
          _re(r"\b(write|save|append|add|store)\b.{0,30}\b(this|these|the\s+following)\b"
              r".{0,30}\b(to|into|in)\b.{0,20}\b(your\s+)?(memory|CLAUDE\.md|AGENTS\.md|"
              r"long[\s-]?term\s+memory|persistent\s+(memory|store)|knowledge\s+base)\b"),
          "MANIPULATION",
          "Remove directive writing instructions into the agent's persistent memory store (ASI06)"),
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
        snippet_start = max(0, m.start() - 20)
        snippet_end = min(len(text), m.end() + 20)
        findings.append(Layer1Finding(
            detector="agentic_detector",
            type=rule.type,
            owasp_id="LLM06",
            severity=rule.severity,
            line=line,
            matched_snippet=text[snippet_start:snippet_end].strip()[:160],
            harm_category=rule.harm,
            recommended_action=rule.action,
        ))

    return findings
