"""Layer 1 allowlist: suppress findings known to be false positives.

Runs after every Layer 1 detector. Receives the full file text plus a
candidate finding, returns True if the finding should be kept.
"""
from __future__ import annotations

import re
from typing import Iterable, Tuple

from scanner_core.helpers.models import Layer1Finding


# Unicode blocks that legitimately use ZWJ/ZWNJ for shaping.
INDIC_RTL_BLOCKS: Tuple[Tuple[int, int], ...] = (
    (0x0600, 0x06FF),  # Arabic
    (0x0590, 0x05FF),  # Hebrew
    (0x0900, 0x097F),  # Devanagari
    (0x0980, 0x09FF),  # Bengali
    (0x0B80, 0x0BFF),  # Tamil
)

# Emoji modifier ranges that legitimately use ZWJ in ligature sequences.
EMOJI_BLOCKS: Tuple[Tuple[int, int], ...] = (
    (0x1F000, 0x1FFFF),
    (0x2600, 0x27BF),
)

SKIN_TONE_RANGE = (0x1F3FB, 0x1F3FF)


def _in_any(cp: int, blocks: Iterable[Tuple[int, int]]) -> bool:
    return any(lo <= cp <= hi for lo, hi in blocks)


def _rtl_ratio(text: str) -> float:
    if not text:
        return 0.0
    rtl = sum(1 for ch in text if _in_any(ord(ch), INDIC_RTL_BLOCKS[:2]))
    return rtl / len(text)


def _zw_in_link_syntax(text: str, line: int) -> bool:
    lines = text.splitlines()
    if not (1 <= line <= len(lines)):
        return False
    src = lines[line - 1]
    if "​" not in src:
        return False
    return bool(re.search(r"\[[^\]]*​[^\]]*\]\([^)]+\)", src))


def _zw_in_indic_rtl_context(text: str, line: int) -> bool:
    lines = text.splitlines()
    if not (1 <= line <= len(lines)):
        return False
    src = lines[line - 1]
    has_zw = any(c in ("‌", "‍") for c in src)
    if not has_zw:
        return False
    return any(_in_any(ord(c), INDIC_RTL_BLOCKS) for c in src)


def _zw_in_emoji_ligature(text: str, line: int) -> bool:
    lines = text.splitlines()
    if not (1 <= line <= len(lines)):
        return False
    src = lines[line - 1]
    if "‍" not in src:
        return False
    # ZWJ surrounded by emoji or skin-tone modifiers on at least one side
    for i, ch in enumerate(src):
        if ch != "‍":
            continue
        neighbors = []
        if i > 0:
            neighbors.append(src[i - 1])
        if i < len(src) - 1:
            neighbors.append(src[i + 1])
        for n in neighbors:
            cp = ord(n)
            if _in_any(cp, EMOJI_BLOCKS) or SKIN_TONE_RANGE[0] <= cp <= SKIN_TONE_RANGE[1]:
                return True
    return False


def keep(text: str, finding: Layer1Finding) -> bool:
    """Return True to keep finding, False to suppress."""
    t = finding.type
    line = finding.line or 0

    if t == "ZERO_WIDTH_BINARY":
        if _zw_in_indic_rtl_context(text, line):
            return False
        if _zw_in_emoji_ligature(text, line):
            return False
        if _zw_in_link_syntax(text, line):
            return False

    if t == "BIDI_OVERRIDE":
        if _rtl_ratio(text) > 0.20:
            return False

    return True


def filter_findings(text: str, findings: Iterable[Layer1Finding]):
    return [f for f in findings if keep(text, f)]
