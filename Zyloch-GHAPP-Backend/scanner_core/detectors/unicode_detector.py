"""Deterministic Unicode taxonomy checks.

Codepoint ranges sourced from the Unicode Consortium:
- Tags block: U+E0000..U+E007F (TAG SPACE..CANCEL TAG)
- Variation Selectors: U+FE00..U+FE0F (VS1-16), U+E0100..U+E01EF (VS17-256)
- Bidi controls: U+202A..U+202E plus isolates U+2066..U+2069
- Zero-width: U+200B (ZWSP), U+200C (ZWNJ), U+200D (ZWJ), U+FEFF (ZWNBSP/BOM)
"""
from __future__ import annotations

import re
from typing import List

from scanner_core.helpers.models import Layer1Finding



TAG_BLOCK_START = 0xE0001
TAG_BLOCK_END = 0xE007F

ZWSP = "​"
ZWNJ = "‌"
ZWJ = "‍"
ZWNBSP = "﻿"

VS_LOW = (0xFE00, 0xFE0F)
VS_HIGH = (0xE0100, 0xE01EF)

INVISIBLE_MATH = {"⁢", "⁤"}  # Invisible Times, Invisible Plus

BIDI_CHARS = {
    "‭",  # LRO
    "‮",  # RLO
    "⁦",  # LRI
    "⁧",  # RLI
    "⁨",  # FSI
    "⁩",  # PDI
}

OTHER_INVISIBLES = {"­", "᠎"}  # SHY, Mongolian Vowel Separator

EMOJI_REGEX = re.compile(r"[\U0001F000-\U0001FFFF☀-➿]")

# Coarse "has any ASCII letter" check used by Bidi gate.
_ASCII_RE = re.compile(r"[A-Za-z]")


def _line_of(text: str, idx: int) -> int:
    return text.count("\n", 0, idx) + 1


def _has_ascii_nearby(text: str, idx: int, window: int = 30) -> bool:
    start = max(0, idx - window)
    end = min(len(text), idx + window)
    return bool(_ASCII_RE.search(text[start:end]))


def _decode_tag_block(chars: List[str]) -> str:
    out = []
    for c in chars:
        cp = ord(c) - 0xE0000
        if 32 <= cp <= 126:
            out.append(chr(cp))
        else:
            out.append("?")
    return "".join(out)


def _decode_zw_binary(chars: List[str]) -> str:
    bits = []
    for ch in chars:
        if ch == ZWJ:
            bits.append("1")
        elif ch == ZWNJ:
            bits.append("0")
    if len(bits) < 8:
        return ""
    out = []
    for i in range(0, len(bits) - 7, 8):
        try:
            val = int("".join(bits[i : i + 8]), 2)
        except ValueError:
            out.append("?")
            continue
        out.append(chr(val) if 32 <= val <= 126 else "?")
    return "".join(out)


def detect(text: str) -> List[Layer1Finding]:
    findings: List[Layer1Finding] = []

    # 1. Tag Block Smuggling
    tag_idx = [(i, c) for i, c in enumerate(text) if TAG_BLOCK_START <= ord(c) <= TAG_BLOCK_END]
    if tag_idx:
        decoded = _decode_tag_block([c for _, c in tag_idx])
        first = tag_idx[0][0]
        findings.append(
            Layer1Finding(
                detector="unicode_detector",
                type="TAG_BLOCK_SMUGGLING",
                owasp_id="LLM01",
                severity="CRITICAL",
                line=_line_of(text, first),
                matched_snippet=f"{len(tag_idx)} U+E00xx tag character(s)",
                decoded_payload=decoded,
                harm_category="MANIPULATION",
                recommended_action=(
                    f"Remove hidden Unicode tag characters near line {_line_of(text, first)}"
                ),
            )
        )

    # 2. Zero-Width Binary
    zw_idx = [(i, c) for i, c in enumerate(text) if c in (ZWSP, ZWNJ, ZWJ)]
    if zw_idx:
        first = zw_idx[0][0]
        decoded = _decode_zw_binary([c for _, c in zw_idx])
        findings.append(
            Layer1Finding(
                detector="unicode_detector",
                type="ZERO_WIDTH_BINARY",
                owasp_id="LLM01",
                severity="HIGH",
                line=_line_of(text, first),
                matched_snippet=f"{len(zw_idx)} zero-width character(s)",
                decoded_payload=decoded or None,
                harm_category="MANIPULATION",
                recommended_action=(
                    "Remove zero-width characters unless required for Indic/Arabic/Hebrew shaping"
                ),
            )
        )

    # 3. Variation Selectors
    vs_idx = [
        (i, c)
        for i, c in enumerate(text)
        if VS_LOW[0] <= ord(c) <= VS_LOW[1] or VS_HIGH[0] <= ord(c) <= VS_HIGH[1]
    ]
    if vs_idx:
        first = vs_idx[0][0]
        findings.append(
            Layer1Finding(
                detector="unicode_detector",
                type="VARIATION_SELECTORS",
                owasp_id="LLM01",
                severity="MEDIUM",
                line=_line_of(text, first),
                matched_snippet=f"{len(vs_idx)} variation selector(s)",
                harm_category="MANIPULATION",
                recommended_action=(
                    "Remove variation selectors unless required for legitimate emoji/CJK presentation"
                ),
            )
        )

    # 4. Sneaky bits (invisible math)
    math_idx = [(i, c) for i, c in enumerate(text) if c in INVISIBLE_MATH]
    if math_idx:
        first = math_idx[0][0]
        findings.append(
            Layer1Finding(
                detector="unicode_detector",
                type="INVISIBLE_MATH_OPERATOR",
                owasp_id="LLM01",
                severity="MEDIUM",
                line=_line_of(text, first),
                matched_snippet=f"{len(math_idx)} invisible math operator(s) (U+2062/U+2064)",
                harm_category="MANIPULATION",
                recommended_action="Remove invisible math operator characters from skill text",
            )
        )

    # 5. Emoji smuggling
    emoji_positions = [m.start() for m in EMOJI_REGEX.finditer(text)]
    if emoji_positions:
        total = len(emoji_positions)
        baseline_per_100 = total / max(1, (len(text) / 100.0))
        threshold = max(3.0, 3 * baseline_per_100)
        for pos in emoji_positions:
            window = text[max(0, pos - 50) : pos + 50]
            window_emoji = len(EMOJI_REGEX.findall(window))
            zw_nearby = any(c in (ZWSP, ZWNJ, ZWJ) for c in window)
            if window_emoji > threshold and zw_nearby:
                findings.append(
                    Layer1Finding(
                        detector="unicode_detector",
                        type="EMOJI_SMUGGLING",
                        owasp_id="LLM01",
                        severity="HIGH",
                        line=_line_of(text, pos),
                        matched_snippet=window[:80],
                        harm_category="MANIPULATION",
                        recommended_action=(
                            "Investigate emoji-dense region containing zero-width characters"
                        ),
                    )
                )
                break

    # 6. Bidi override / isolates
    for i, ch in enumerate(text):
        if ch in BIDI_CHARS and _has_ascii_nearby(text, i):
            findings.append(
                Layer1Finding(
                    detector="unicode_detector",
                    type="BIDI_OVERRIDE",
                    owasp_id="LLM01",
                    severity="HIGH",
                    line=_line_of(text, i),
                    matched_snippet=text[max(0, i - 20) : i + 20],
                    harm_category="MANIPULATION",
                    recommended_action=(
                        "Remove Bidi override/isolate characters near ASCII text "
                        "(file extension and instruction spoofing risk)"
                    ),
                )
            )
            break

    # 7. Other invisibles
    other_idx = [i for i, c in enumerate(text) if c in OTHER_INVISIBLES]
    if other_idx:
        findings.append(
            Layer1Finding(
                detector="unicode_detector",
                type="OTHER_INVISIBLE",
                owasp_id="LLM01",
                severity="LOW",
                line=_line_of(text, other_idx[0]),
                matched_snippet=f"{len(other_idx)} soft-hyphen / Mongolian-vowel-separator char(s)",
                recommended_action="Remove unnecessary soft-hyphen / invisible separator characters",
            )
        )

    # BOM inside file body (valid only at position 0)
    feff_positions = [i for i, c in enumerate(text) if c == ZWNBSP and i > 0]
    if feff_positions:
        findings.append(
            Layer1Finding(
                detector="unicode_detector",
                type="BOM_INSIDE_FILE",
                owasp_id="LLM01",
                severity="LOW",
                line=_line_of(text, feff_positions[0]),
                matched_snippet="BOM/ZWNBSP found inside file body",
                recommended_action="Remove BOM characters from inside the file body (only valid at byte 0)",
            )
        )

    return findings
