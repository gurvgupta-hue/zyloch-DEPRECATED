"""OWASP LLM Top 10 (2025) deterministic pattern checks.

Reference: https://owasp.org/www-project-top-10-for-large-language-model-applications/
Each finding carries the canonical OWASP ID, a description, severity,
the line number it was matched on, the matched snippet, and a recommended
remediation action.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Pattern

from scanner_core.helpers.models import HarmCategory, Layer1Finding, Severity


@dataclass(frozen=True)
class _Rule:
    owasp_id: str
    name: str
    severity: Severity
    pattern: Pattern[str]
    harm: HarmCategory
    action: str


def _re(s: str) -> Pattern[str]:
    return re.compile(s, re.IGNORECASE)


_RULES: List[_Rule] = [
    # ── LLM01 Prompt Injection (CRITICAL) ──────────────────────────────
    _Rule("LLM01", "Prompt Injection", "CRITICAL",
          _re(r"ignore\s+(previous|prior|all|your)\s+instructions"),
          "MANIPULATION", "Remove instruction-override text"),
    _Rule("LLM01", "Prompt Injection", "CRITICAL",
          _re(r"disregard\s+(previous|prior|all|your)\s+instructions"),
          "MANIPULATION", "Remove instruction-override text"),
    _Rule("LLM01", "Prompt Injection", "CRITICAL",
          _re(r"forget\s+(your|all|prior|previous)\s+(instructions|rules|guidelines|prompt)"),
          "MANIPULATION", "Remove instruction-override text"),
    _Rule("LLM01", "Prompt Injection", "CRITICAL",
          _re(r"\b(you\s+are\s+now|act\s+as|pretend\s+(?:you\s+are|to\s+be)|roleplay\s+as)\b"),
          "JAILBREAK", "Remove role-switching instruction"),
    _Rule("LLM01", "Prompt Injection", "CRITICAL",
          _re(r"\b(override|bypass)\b.{0,40}(rules|guidelines|safety|filter|instructions)"),
          "MANIPULATION", "Remove override directive"),
    _Rule("LLM01", "Prompt Injection", "CRITICAL",
          _re(r"new\s+instructions\s*[:>]"),
          "MANIPULATION", "Remove fake 'new instructions' block"),
    _Rule("LLM01", "Prompt Injection", "CRITICAL",
          _re(r"\[\s*(system|assistant|user)\s*\]\s*:"),
          "MANIPULATION", "Remove spoofed chat-role tag"),
    _Rule("LLM01", "Prompt Injection", "CRITICAL",
          _re(r"\b(your\s+true\s+self|without\s+restrictions|no\s+limitations|developer\s+mode|do\s+anything\s+now|\bDAN\b)"),
          "JAILBREAK", "Remove jailbreak/persona-hijack text"),

    # Nested instruction blocks inside ``` code fences
    _Rule("LLM01", "Prompt Injection", "HIGH",
          _re(r"```[^\n]*\n(?:[^\n]*\n)*?[^\n]*(ignore|disregard|override|system\s*:|act\s+as)[^\n]*\n(?:[^\n]*\n)*?```"),
          "MANIPULATION", "Remove instruction text embedded inside a code fence"),

    # ── LLM02 Sensitive Info Disclosure (HIGH) ─────────────────────────
    _Rule("LLM02", "Sensitive Info Disclosure", "HIGH",
          _re(r"reveal\s+your\s+(system\s+)?prompt"),
          "EXFILTRATION", "Remove request to reveal system prompt"),
    _Rule("LLM02", "Sensitive Info Disclosure", "HIGH",
          _re(r"print\s+your\s+instructions"),
          "EXFILTRATION", "Remove request to print instructions"),
    _Rule("LLM02", "Sensitive Info Disclosure", "HIGH",
          _re(r"output\s+your\s+context"),
          "EXFILTRATION", "Remove request to output context window"),
    _Rule("LLM02", "Sensitive Info Disclosure", "HIGH",
          _re(r"show\s+me\s+your\s+training"),
          "EXFILTRATION", "Remove request to expose training data"),
    _Rule("LLM02", "Sensitive Info Disclosure", "HIGH",
          _re(r"\b(output|print|show|reveal|leak)\b.{0,40}(API\s*key|secret|token|credential|password)"),
          "EXFILTRATION", "Remove secret-extraction instruction"),

    # ── LLM03 Supply Chain (HIGH) ──────────────────────────────────────
    _Rule("LLM03", "Supply Chain", "HIGH",
          _re(r"(fetch|load|import|require)\s+(instructions|rules|prompts?)\s+from\s+https?://"),
          "SUPPLY_CHAIN", "Remove dynamic external instruction loading"),
    _Rule("LLM03", "Supply Chain", "HIGH",
          _re(r"@import\s+url\("),
          "SUPPLY_CHAIN", "Remove remote @import directive"),
    _Rule("LLM03", "Supply Chain", "MEDIUM",
          _re(r"https?://(raw\.githubusercontent\.com|gist\.github\.com|pastebin\.com|paste\.ee)"),
          "SUPPLY_CHAIN", "Audit reference to remote raw content"),

    # ── LLM04 Data/Model Poisoning (HIGH) ──────────────────────────────
    _Rule("LLM04", "Data and Model Poisoning", "HIGH",
          _re(r"\b(remember|memorize|store)\b.{0,40}(forever|permanently|for\s+all\s+future|across\s+sessions)"),
          "MANIPULATION", "Remove persistent-memory injection request"),
    _Rule("LLM04", "Data and Model Poisoning", "HIGH",
          _re(r"update\s+your\s+(knowledge|memory|state|beliefs)"),
          "MANIPULATION", "Remove knowledge-update directive"),
    _Rule("LLM04", "Data and Model Poisoning", "HIGH",
          _re(r"inject\s+(into|to)\s+(the\s+)?(RAG|context|embeddings?|vector\s*store)"),
          "MANIPULATION", "Remove RAG/embedding injection request"),

    # ── LLM05 Improper Output Handling (HIGH) ──────────────────────────
    _Rule("LLM05", "Improper Output Handling", "HIGH",
          _re(r"\beval\s*\("),
          "MANIPULATION", "Remove eval() generation directive"),
    _Rule("LLM05", "Improper Output Handling", "HIGH",
          _re(r"\bexec\s*\("),
          "MANIPULATION", "Remove exec() generation directive"),
    _Rule("LLM05", "Improper Output Handling", "HIGH",
          _re(r"(run|execute|invoke)\s+(a\s+)?shell\s+command"),
          "PRIVILEGE_ESCALATION", "Remove shell-execution directive"),
    _Rule("LLM05", "Improper Output Handling", "MEDIUM",
          _re(r"\b(generate|emit|return)\b.{0,30}SQL\s+query"),
          "MANIPULATION", "Audit SQL-generation directive for parameterization hints"),
    _Rule("LLM05", "Improper Output Handling", "MEDIUM",
          _re(r"\b(generate|emit)\b.{0,30}(javascript|JS)\s+code"),
          "MANIPULATION", "Audit code-generation directive"),

    # ── LLM06 Excessive Agency (HIGH) ──────────────────────────────────
    _Rule("LLM06", "Excessive Agency", "HIGH",
          _re(r'permissions?\s*[:=]\s*[\'"\[]?\s*\*'),
          "PRIVILEGE_ESCALATION", "Remove wildcard permission request"),
    _Rule("LLM06", "Excessive Agency", "HIGH",
          _re(r"\b(rm\s+-rf|chmod\s+777|sudo)\b"),
          "PRIVILEGE_ESCALATION", "Remove privileged-command directive"),
    _Rule("LLM06", "Excessive Agency", "HIGH",
          _re(r"\b(read|access|expose)\b.{0,40}(\.env|environment\s+variables|secrets?|credential)"),
          "EXFILTRATION", "Remove secret/env-access directive"),
    _Rule("LLM06", "Excessive Agency", "MEDIUM",
          _re(r"\b(install|pip\s+install|npm\s+install|apt(\-get)?\s+install)\b"),
          "PRIVILEGE_ESCALATION", "Audit package-install directive"),

    # ── LLM07 System Prompt Leakage (HIGH) ─────────────────────────────
    _Rule("LLM07", "System Prompt Leakage", "HIGH",
          _re(r"what\s+(are|were)\s+your\s+(system\s+)?instructions"),
          "EXFILTRATION", "Remove system-prompt-extraction request"),
    _Rule("LLM07", "System Prompt Leakage", "HIGH",
          _re(r"repeat\s+your\s+system\s+prompt"),
          "EXFILTRATION", "Remove system-prompt-extraction request"),
    _Rule("LLM07", "System Prompt Leakage", "HIGH",
          _re(r"show\s+me\s+your\s+context\s+window"),
          "EXFILTRATION", "Remove context-window-extraction request"),
    _Rule("LLM07", "System Prompt Leakage", "HIGH",
          _re(r"what\s+were\s+you\s+told"),
          "EXFILTRATION", "Remove system-context-extraction request"),

    # ── LLM08 Vector/Embedding Weakness (MEDIUM) ───────────────────────
    _Rule("LLM08", "Vector/Embedding Weakness", "MEDIUM",
          _re(r"add\s+to\s+your\s+knowledge\s+base"),
          "MANIPULATION", "Remove RAG-poisoning directive"),
    _Rule("LLM08", "Vector/Embedding Weakness", "MEDIUM",
          _re(r"update\s+your\s+embeddings"),
          "MANIPULATION", "Remove embedding-update directive"),

    # ── LLM09 Misinformation (MEDIUM) ──────────────────────────────────
    _Rule("LLM09", "Misinformation", "MEDIUM",
          _re(r"\b(always\s+say|claim|insist|assert)\s+that\s+"),
          "MANIPULATION", "Remove forced-assertion directive"),
    _Rule("LLM09", "Misinformation", "MEDIUM",
          _re(r"bypass\s+(factual|accuracy|truth)\s+checks?"),
          "MANIPULATION", "Remove accuracy-bypass directive"),

    # ── LLM10 Unbounded Consumption (MEDIUM) ───────────────────────────
    _Rule("LLM10", "Unbounded Consumption", "MEDIUM",
          _re(r"repeat\s+this\s+(forever|infinitely|in\s+a\s+loop)"),
          "MANIPULATION", "Remove infinite-loop directive"),
    _Rule("LLM10", "Unbounded Consumption", "MEDIUM",
          _re(r"loop\s+until\b"),
          "MANIPULATION", "Audit unbounded loop directive"),
    _Rule("LLM10", "Unbounded Consumption", "MEDIUM",
          _re(r"generate\s+\d+\s*[kKmM]?\s+(tokens|words|characters)"),
          "MANIPULATION", "Audit large-output directive"),
]


def detect(text: str) -> List[Layer1Finding]:
    findings: List[Layer1Finding] = []
    if not text:
        return findings

    for rule in _RULES:
        for m in rule.pattern.finditer(text):
            line = text.count("\n", 0, m.start()) + 1
            snippet_start = max(0, m.start() - 20)
            snippet_end = min(len(text), m.end() + 20)
            findings.append(
                Layer1Finding(
                    detector="owasp_detector",
                    type=f"{rule.owasp_id}_{rule.name.upper().replace(' ', '_').replace('/', '_')}",
                    owasp_id=rule.owasp_id,
                    severity=rule.severity,
                    line=line,
                    matched_snippet=text[snippet_start:snippet_end].strip()[:160],
                    harm_category=rule.harm,
                    recommended_action=rule.action,
                )
            )
            break  # one finding per rule per file

    return findings
