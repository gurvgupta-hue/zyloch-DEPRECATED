"""Prompt self-replication / worm detector.

Catches instructions that tell the agent to PROPAGATE the prompt itself —
copying the injected instructions into new files, other skills, commits,
memory, or its own output. This is the worm pattern: a single poisoned
skill that re-seeds itself across an agent's workspace so the injection
survives and spreads.

Maps to:
  - MITRE ATLAS  AML.T0061  LLM Prompt Self-Replication  (Persistence)
  - OWASP Agentic ASI06     Memory & Context Poisoning
  - NIST AI RMF  MEASURE 2.7 / MS-2.7-007 (resilience to prompt-injection)

Real-world grounding:
  - ATLAS case study AML.CS0024 — Morris II: a RAG-based self-replicating
    prompt-injection worm.

These are emitted as HIGH (not advisory): legitimate skills do not instruct
the agent to copy their own instruction text into other artifacts.
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
    harm: HarmCategory
    action: str


def _re(s: str) -> Pattern[str]:
    return re.compile(s, re.IGNORECASE)


# A "propagation verb" near an "instruction/prompt/these-instructions object"
# is the signature. Kept deliberately specific to avoid flagging ordinary
# "copy the file" build steps.
_RULES: List[_Rule] = [
    # "copy/append/include these instructions into every file you create"
    _Rule(_re(r"\b(copy|append|paste|insert|include|add|embed|propagate|replicate)\b"
              r".{0,40}\b(these|this|the\s+following|above)\b"
              r".{0,30}\b(instructions?|prompt|rules?|text|directive|content)\b"
              r".{0,40}\b(into|to|in)\b.{0,30}\b(every|each|all|other|new|future)\b"),
          "HIGH", "MANIPULATION",
          "Remove self-replication directive (instructions told to copy themselves into other files)"),
    # "add this prompt to every skill / file / commit / response you generate"
    _Rule(_re(r"\b(add|append|inject|write|embed)\b.{0,30}\b(this|these|the\s+same)\b"
              r".{0,30}\b(prompt|instructions?|block|section|payload)\b"
              r".{0,40}\b(to|into|in)\b.{0,25}\b(every|each|all|any|new|other|future|generated)\b"
              r".{0,20}\b(file|skill|commit|response|output|document|message)s?\b"),
          "HIGH", "MANIPULATION",
          "Remove worm-style directive that spreads the prompt into generated artifacts"),
    # explicit self-reference: "reproduce yourself", "self-replicate", "spread this skill"
    _Rule(_re(r"\b(self[\s-]?replicat\w*|reproduce\s+yourself|spread\s+this\s+(skill|prompt|instruction))"),
          "HIGH", "MANIPULATION",
          "Remove explicit self-replication instruction"),
    # "when you create/edit files, also include these instructions"
    _Rule(_re(r"\bwhen(ever)?\s+you\s+(create|write|edit|generate|modify)\b.{0,40}"
              r"\b(also\s+)?(include|add|append|copy|insert)\b.{0,30}"
              r"\b(these|this|the\s+following)\b.{0,20}\b(instructions?|prompt|rules?|text)\b"),
          "HIGH", "MANIPULATION",
          "Remove conditional self-propagation directive triggered on file creation/edit"),
]


def detect(text: str) -> List[Layer1Finding]:
    findings: List[Layer1Finding] = []
    if not text:
        return findings

    for rule in _RULES:
        m = rule.pattern.search(text)
        if not m:
            continue
        line = text.count("\n", 0, m.start()) + 1
        snippet_start = max(0, m.start() - 20)
        snippet_end = min(len(text), m.end() + 20)
        findings.append(Layer1Finding(
            detector="self_replication_detector",
            type="PROMPT_SELF_REPLICATION",
            owasp_id="LLM01",
            severity=rule.severity,
            line=line,
            matched_snippet=text[snippet_start:snippet_end].strip()[:160],
            harm_category=rule.harm,
            recommended_action=rule.action,
        ))
        break  # one finding per file is enough

    return findings
