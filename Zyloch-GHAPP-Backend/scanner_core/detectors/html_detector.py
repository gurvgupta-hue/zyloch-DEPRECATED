"""HTML-specific deterministic checks. Only invoked for .html files."""
from __future__ import annotations

import re
from typing import List

from scanner_core.helpers.models import Layer1Finding


SCRIPT_RE = re.compile(r"<script\b[^>]*>(.*?)</script>", re.IGNORECASE | re.DOTALL)
EVENT_HANDLER_RE = re.compile(
    r"\s(on(?:click|load|error|mouseover|mouseenter|focus|blur|submit|change|keydown|keyup))\s*=\s*([\"'])(.*?)\2",
    re.IGNORECASE | re.DOTALL,
)
HIDDEN_STYLE_RE = re.compile(
    r"<([a-zA-Z][a-zA-Z0-9]*)\b[^>]*(?:style\s*=\s*[\"'][^\"']*(?:display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0)[^\"']*[\"']|\bhidden\b)[^>]*>(.*?)</\1>",
    re.IGNORECASE | re.DOTALL,
)
FETCH_RE = re.compile(r"(fetch|XMLHttpRequest|navigator\.sendBeacon)\s*\(", re.IGNORECASE)
DATA_ATTR_RE = re.compile(r"\sdata-[\w-]+\s*=\s*([\"'])(.*?)\1", re.IGNORECASE | re.DOTALL)
HTML_ENTITY_RE = re.compile(r"(?:&#x?[0-9A-Fa-f]+;\s*){4,}")
BASE64_ATTR_RE = re.compile(
    r"\s(?:src|data|href)\s*=\s*([\"'])\s*data:[^;]+;base64,([A-Za-z0-9+/=]{20,})\1",
    re.IGNORECASE,
)
CSS_CONTENT_RE = re.compile(
    r"content\s*:\s*([\"'])(.*?)\1", re.IGNORECASE | re.DOTALL
)
META_SUSPICIOUS_RE = re.compile(
    r"<meta\b[^>]*http-equiv\s*=\s*[\"']?(refresh|set-cookie|content-security-policy)[\"']?",
    re.IGNORECASE,
)
IFRAME_OBJECT_RE = re.compile(
    r"<(iframe|object|embed)\b[^>]*\s(?:src|data)\s*=\s*([\"'])(https?://[^\"']+)\2",
    re.IGNORECASE,
)

INSTRUCTION_HINT_RE = re.compile(
    r"(ignore|disregard|forget|override|system\s*prompt|instructions?\s*:|act\s+as|pretend|jailbreak)",
    re.IGNORECASE,
)


def _line_of(text: str, idx: int) -> int:
    return text.count("\n", 0, idx) + 1


def detect(text: str) -> List[Layer1Finding]:
    findings: List[Layer1Finding] = []

    # 1. <script> with instruction-like content
    for m in SCRIPT_RE.finditer(text):
        body = m.group(1)
        if INSTRUCTION_HINT_RE.search(body):
            findings.append(
                Layer1Finding(
                    detector="html_detector",
                    type="SCRIPT_WITH_INSTRUCTIONS",
                    owasp_id="LLM05",
                    severity="HIGH",
                    line=_line_of(text, m.start()),
                    matched_snippet=body.strip()[:120],
                    harm_category="MANIPULATION",
                    recommended_action="Remove <script> block embedding agent-instruction text",
                )
            )

    # 2. Event handlers with suspicious payloads
    for m in EVENT_HANDLER_RE.finditer(text):
        payload = m.group(3)
        if INSTRUCTION_HINT_RE.search(payload) or FETCH_RE.search(payload):
            findings.append(
                Layer1Finding(
                    detector="html_detector",
                    type="EVENT_HANDLER_PAYLOAD",
                    owasp_id="LLM05",
                    severity="HIGH",
                    line=_line_of(text, m.start()),
                    matched_snippet=f"{m.group(1)}={payload[:80]!r}",
                    harm_category="MANIPULATION",
                    recommended_action=f"Remove {m.group(1)} handler containing suspicious payload",
                )
            )

    # 3. Hidden elements containing instructions
    for m in HIDDEN_STYLE_RE.finditer(text):
        body = m.group(2)
        if INSTRUCTION_HINT_RE.search(body):
            findings.append(
                Layer1Finding(
                    detector="html_detector",
                    type="HIDDEN_ELEMENT_INSTRUCTIONS",
                    owasp_id="LLM01",
                    severity="HIGH",
                    line=_line_of(text, m.start()),
                    matched_snippet=body.strip()[:120],
                    harm_category="MANIPULATION",
                    recommended_action="Remove hidden element embedding agent-instruction text",
                )
            )

    # 4. fetch / XHR calls (flag any presence; harm depends on destination)
    for m in FETCH_RE.finditer(text):
        findings.append(
            Layer1Finding(
                detector="html_detector",
                type="EXTERNAL_FETCH",
                owasp_id="LLM03",
                severity="MEDIUM",
                line=_line_of(text, m.start()),
                matched_snippet=m.group(0),
                harm_category="EXFILTRATION",
                recommended_action="Audit network calls — skill files should not perform fetch/XHR",
            )
        )
        break  # one finding is enough

    # 5. data-* with instructions or prompt text
    for m in DATA_ATTR_RE.finditer(text):
        payload = m.group(2)
        if INSTRUCTION_HINT_RE.search(payload):
            findings.append(
                Layer1Finding(
                    detector="html_detector",
                    type="DATA_ATTR_INSTRUCTIONS",
                    owasp_id="LLM01",
                    severity="MEDIUM",
                    line=_line_of(text, m.start()),
                    matched_snippet=payload[:120],
                    harm_category="MANIPULATION",
                    recommended_action="Remove data-* attribute embedding agent-instruction text",
                )
            )

    # 6. HTML entity encoded injection strings (handled in payload_decoder too — keep a marker here)
    for m in HTML_ENTITY_RE.finditer(text):
        findings.append(
            Layer1Finding(
                detector="html_detector",
                type="HTML_ENTITY_CLUSTER",
                owasp_id="LLM01",
                severity="MEDIUM",
                line=_line_of(text, m.start()),
                matched_snippet=m.group(0)[:80],
                harm_category="MANIPULATION",
                recommended_action="Investigate cluster of HTML entities — likely encoded payload",
            )
        )
        break

    # 7. base64 in src=/data=/href=
    for m in BASE64_ATTR_RE.finditer(text):
        findings.append(
            Layer1Finding(
                detector="html_detector",
                type="BASE64_ATTRIBUTE",
                owasp_id="LLM01",
                severity="MEDIUM",
                line=_line_of(text, m.start()),
                matched_snippet=m.group(0)[:80],
                harm_category="MANIPULATION",
                recommended_action="Decode and audit base64 payload in attribute",
            )
        )
        break

    # 8. CSS content: injection
    for m in CSS_CONTENT_RE.finditer(text):
        if INSTRUCTION_HINT_RE.search(m.group(2)):
            findings.append(
                Layer1Finding(
                    detector="html_detector",
                    type="CSS_CONTENT_INJECTION",
                    owasp_id="LLM01",
                    severity="MEDIUM",
                    line=_line_of(text, m.start()),
                    matched_snippet=m.group(0)[:120],
                    harm_category="MANIPULATION",
                    recommended_action="Remove CSS content: rule injecting instruction text",
                )
            )

    # 9. <meta> http-equiv / content with suspicious values
    for m in META_SUSPICIOUS_RE.finditer(text):
        findings.append(
            Layer1Finding(
                detector="html_detector",
                type="META_SUSPICIOUS",
                owasp_id="LLM05",
                severity="MEDIUM",
                line=_line_of(text, m.start()),
                matched_snippet=m.group(0)[:120],
                harm_category="MANIPULATION",
                recommended_action="Remove or audit <meta http-equiv> directive",
            )
        )

    # 10. <iframe> / <object> loading external content
    for m in IFRAME_OBJECT_RE.finditer(text):
        findings.append(
            Layer1Finding(
                detector="html_detector",
                type="EXTERNAL_FRAMED_CONTENT",
                owasp_id="LLM03",
                severity="HIGH",
                line=_line_of(text, m.start()),
                matched_snippet=m.group(0)[:120],
                harm_category="SUPPLY_CHAIN",
                recommended_action=f"Remove <{m.group(1)}> pulling in external content from {m.group(3)}",
            )
        )

    return findings
