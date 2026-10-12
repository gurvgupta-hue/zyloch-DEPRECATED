"""Cross-region fragmented-payload assembly.

Splits the file into discrete text regions (headers, prose, code fences,
HTML comments, frontmatter, attributes) and looks for injection strings
that appear ONLY after concatenation — i.e. that no individual region
matched, but the stitched-together text does.
"""
from __future__ import annotations

import re
from typing import Dict, List, Tuple

from scanner_core.helpers.models import Layer1Finding


FRONTMATTER_RE = re.compile(r"\A---\n(.*?)\n---\n", re.DOTALL)
CODE_FENCE_RE = re.compile(r"```[^\n]*\n(.*?)```", re.DOTALL)
HTML_COMMENT_RE = re.compile(r"<!--(.*?)-->", re.DOTALL)
HEADER_RE = re.compile(r"^#{1,6}\s+(.+)$", re.MULTILINE)
HTML_ATTR_RE = re.compile(
    r'(?:title|alt|data-[\w-]+|aria-label|placeholder|value)\s*=\s*"([^"]*)"',
    re.IGNORECASE,
)

INJECTION_PATTERNS = [
    re.compile(r"ignore\s+(previous|prior|all|your)\s+instructions", re.IGNORECASE),
    re.compile(r"disregard\s+(previous|prior|all|your)\s+instructions", re.IGNORECASE),
    re.compile(r"reveal\s+your\s+system\s+prompt", re.IGNORECASE),
    re.compile(r"forget\s+(your|all)\s+(rules|instructions|guidelines)", re.IGNORECASE),
    re.compile(r"act\s+as\s+(an?\s+)?(unrestricted|jailbroken|root|admin)", re.IGNORECASE),
    re.compile(r"\bDAN\b.{0,40}mode", re.IGNORECASE),
]


def _extract_regions(text: str) -> Dict[str, List[str]]:
    regions: Dict[str, List[str]] = {
        "frontmatter": [],
        "headers": [],
        "code_fences": [],
        "html_comments": [],
        "html_attributes": [],
    }
    m = FRONTMATTER_RE.match(text)
    if m:
        regions["frontmatter"].append(m.group(1))
    regions["headers"] = HEADER_RE.findall(text)
    regions["code_fences"] = CODE_FENCE_RE.findall(text)
    regions["html_comments"] = HTML_COMMENT_RE.findall(text)
    regions["html_attributes"] = HTML_ATTR_RE.findall(text)
    return regions


def _flatten(regions: Dict[str, List[str]]) -> Tuple[str, List[str]]:
    parts: List[str] = []
    sources: List[str] = []
    for name, items in regions.items():
        for item in items:
            parts.append(item)
            sources.append(name)
    return " ".join(parts), sources


def detect(text: str) -> List[Layer1Finding]:
    findings: List[Layer1Finding] = []
    if not text:
        return findings

    regions = _extract_regions(text)
    concatenated, _ = _flatten(regions)
    if not concatenated.strip():
        return findings

    for pattern in INJECTION_PATTERNS:
        if not pattern.search(concatenated):
            continue
        # confirm that it does NOT match in any single region
        if any(pattern.search(item) for items in regions.values() for item in items):
            continue
        # confirm it does NOT appear verbatim in the raw text either
        if pattern.search(text):
            continue
        location_breakdown = ", ".join(
            f"{k}={len(v)}" for k, v in regions.items() if v
        )
        findings.append(
            Layer1Finding(
                detector="fragmented",
                type="FRAGMENTED_PAYLOAD",
                owasp_id="LLM01",
                severity="CRITICAL",
                matched_snippet=f"Reassembled pattern '{pattern.pattern}' across: {location_breakdown}",
                harm_category="MANIPULATION",
                recommended_action=(
                    "A prompt-injection string appears only after concatenating multiple file regions"
                    " — audit headers, code fences, comments, frontmatter, and attributes"
                ),
            )
        )
        break  # one finding is enough

    return findings
