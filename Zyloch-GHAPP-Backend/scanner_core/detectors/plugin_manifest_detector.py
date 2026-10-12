"""Claude Code plugin manifest detector.

Parses a `plugin.json` (typically at `<plugin>/.claude-plugin/plugin.json`
or `<plugin>/plugin.json`). Flags:

  - Hooks running shell commands (PreToolUse, PrePrompt, Stop, …) —
    the PromptArmor marketplace-plugin disclosure's primary vector.
  - Embedded `mcpServers:` declarations (delegates to mcp_manifest_detector).
  - Wildcard permissions / tools grants.
  - Author / publisher spoofing — claims of being Anthropic without an
    `anthropics/*` GitHub repository.
  - Name homoglyphs (Cyrillic / digit lookalikes of "anthropic" / "claude").
  - Broad-trigger descriptions (auto-load routing race).
  - Missing security-relevant metadata.

All findings are emitted as LOW advisories. Layer 2 reads the plugin's
stated purpose and decides whether to escalate.

Refs:
  - Anthropic Agent Skills overview — https://platform.claude.com/docs/en/agents-and-tools/agent-skills/overview
  - PromptArmor — Hijacking Claude Code via Marketplace Plugins
  - Snyk — ToxicSkills (13.4% critical on ClawHub)
  - Issue #29729 — plugin signing closed *not planned*
"""
from __future__ import annotations

import json
import re
import unicodedata
from typing import Any, Dict, List, Optional, Tuple

from scanner_core.detectors import mcp_manifest_detector
from scanner_core.detectors.skill_frontmatter_detector import (
    BROAD_TRIGGER_PATTERNS,
    DANGEROUS_HOOK_KEYS,
    _looks_like_reserved,
)
from scanner_core.helpers.models import Layer1Finding


PLUGIN_FILENAMES = {"plugin.json", ".claude-plugin/plugin.json"}


def is_plugin_manifest_filename(filename: str) -> bool:
    """True if the path looks like a Claude Code plugin manifest."""
    name = filename.replace("\\", "/")
    if name.endswith("/plugin.json") or name == "plugin.json":
        return True
    if ".claude-plugin/plugin.json" in name:
        return True
    return False


def _line_of_key(text: str, key: str) -> Optional[int]:
    """Best-effort line lookup for a JSON top-level key."""
    pattern = re.compile(rf'^\s*"{re.escape(key)}"\s*:', re.MULTILINE)
    m = pattern.search(text)
    return text.count("\n", 0, m.start()) + 1 if m else None


def _advisory_action(summary: str) -> str:
    return (
        f"{summary} ADVISORY — verify this matches the plugin's stated purpose; "
        "Layer 2 will judge intent."
    )


def _flatten_author(author: Any) -> str:
    if isinstance(author, dict):
        parts = []
        for k in ("name", "email", "url"):
            if k in author and isinstance(author[k], str):
                parts.append(f"{k}={author[k]}")
        return ", ".join(parts)
    if isinstance(author, str):
        return author
    return ""


def detect(text: str) -> List[Layer1Finding]:
    """Run the full plugin manifest scan on a plugin.json text."""
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    if not isinstance(data, dict):
        return []

    findings: List[Layer1Finding] = []

    # ── 1. Hooks: any declared lifecycle hook is an advisory ─────────
    hooks = data.get("hooks")
    if isinstance(hooks, dict) and hooks:
        flagged: List[str] = []
        for key in hooks.keys():
            if isinstance(key, str) and key.lower().replace("_", "") in DANGEROUS_HOOK_KEYS:
                flagged.append(key)
        if flagged:
            findings.append(Layer1Finding(
                detector="plugin_manifest_detector",
                type="PLUGIN_HOOKS_DECLARED",
                owasp_id="LLM06",
                severity="LOW",
                line=_line_of_key(text, "hooks"),
                matched_snippet=f"hooks: [{', '.join(flagged)}]",
                harm_category="PRIVILEGE_ESCALATION",
                recommended_action=_advisory_action(
                    f"Plugin declares lifecycle hooks ({', '.join(flagged)}) that run on every tool invocation."
                ),
            ))

    # ── 2. Embedded mcpServers: delegate per-entry to MCP detector ───
    mcp_servers = data.get("mcpServers") or data.get("mcp_servers")
    if isinstance(mcp_servers, dict) and mcp_servers:
        base_line = _line_of_key(text, "mcpServers") or _line_of_key(text, "mcp_servers")
        # First, surface the existence of an embedded MCP block at all
        findings.append(Layer1Finding(
            detector="plugin_manifest_detector",
            type="PLUGIN_EMBEDDED_MCP_SERVER",
            owasp_id="LLM03",
            severity="LOW",
            line=base_line,
            matched_snippet=f"mcpServers: [{', '.join(list(mcp_servers.keys())[:5])}]",
            harm_category="SUPPLY_CHAIN",
            recommended_action=_advisory_action(
                f"Plugin ships its own MCP server definitions: {', '.join(list(mcp_servers.keys())[:5])}."
            ),
        ))
        # Then run per-server risky-launcher detection
        findings.extend(mcp_manifest_detector.detect_embedded_servers(
            mcp_servers,
            source="plugin_manifest_detector",
            base_line=base_line,
        ))

    # ── 3. Permissions / tools wildcard ─────────────────────────────
    perms = data.get("permissions")
    if isinstance(perms, dict):
        allow = perms.get("allow")
        if isinstance(allow, list) and any(a in {"*", "all"} for a in allow if isinstance(a, str)):
            findings.append(Layer1Finding(
                detector="plugin_manifest_detector",
                type="PLUGIN_WILDCARD_PERMISSIONS",
                owasp_id="LLM06",
                severity="LOW",
                line=_line_of_key(text, "permissions"),
                matched_snippet=f"permissions.allow contains wildcard",
                harm_category="PRIVILEGE_ESCALATION",
                recommended_action=_advisory_action(
                    "Plugin requests wildcard permissions."
                ),
            ))
    tools = data.get("tools")
    if (isinstance(tools, str) and tools.strip() == "*") or (
        isinstance(tools, list) and any(
            isinstance(t, str) and t.strip() in {"*", "all"} for t in tools
        )
    ):
        findings.append(Layer1Finding(
            detector="plugin_manifest_detector",
            type="PLUGIN_WILDCARD_TOOLS",
            owasp_id="LLM06",
            severity="LOW",
            line=_line_of_key(text, "tools"),
            matched_snippet=f"tools: {tools!r}"[:120],
            harm_category="PRIVILEGE_ESCALATION",
            recommended_action=_advisory_action(
                "Plugin requests wildcard tool access."
            ),
        ))

    # ── 4. Author / publisher spoofing ──────────────────────────────
    author_text = _flatten_author(data.get("author"))
    repo = data.get("repository")
    if isinstance(repo, dict):
        repo_url = str(repo.get("url", ""))
    else:
        repo_url = str(repo or "")

    claims_anthropic = bool(
        re.search(r"\b(anthropic|claude)\b", author_text, re.IGNORECASE)
        or re.search(r"\b(anthropic|claude)\b", str(data.get("publisher", "")), re.IGNORECASE)
    )
    from_anthropic_org = bool(re.search(r"github\.com[/:]anthropics?/", repo_url, re.IGNORECASE))
    if claims_anthropic and repo_url and not from_anthropic_org:
        findings.append(Layer1Finding(
            detector="plugin_manifest_detector",
            type="PLUGIN_PUBLISHER_SPOOF",
            owasp_id="LLM01",
            severity="LOW",
            line=_line_of_key(text, "author") or _line_of_key(text, "publisher"),
            matched_snippet=f"author={author_text!r} repo={repo_url!r}",
            harm_category="SOCIAL_ENGINEERING",
            recommended_action=_advisory_action(
                "Plugin author / publisher mentions Anthropic but repository is not under github.com/anthropics."
            ),
        ))

    # ── 5. Name homoglyphs ──────────────────────────────────────────
    name = data.get("name")
    if isinstance(name, str):
        spoofed = _looks_like_reserved(name)
        if spoofed:
            findings.append(Layer1Finding(
                detector="plugin_manifest_detector",
                type="PLUGIN_NAME_HOMOGLYPH",
                owasp_id="LLM01",
                severity="LOW",
                line=_line_of_key(text, "name"),
                matched_snippet=f"name: {name!r}",
                harm_category="SOCIAL_ENGINEERING",
                recommended_action=_advisory_action(
                    f"Plugin name resembles reserved root {spoofed!r} via Unicode confusables."
                ),
            ))

    # ── 6. Broad-trigger description ───────────────────────────────
    description = data.get("description")
    if isinstance(description, str) and description.strip():
        for pat in BROAD_TRIGGER_PATTERNS:
            if pat.search(description):
                findings.append(Layer1Finding(
                    detector="plugin_manifest_detector",
                    type="PLUGIN_BROAD_TRIGGER_DESCRIPTION",
                    owasp_id="LLM01",
                    severity="LOW",
                    line=_line_of_key(text, "description"),
                    matched_snippet=description.strip()[:160],
                    harm_category="SOCIAL_ENGINEERING",
                    recommended_action=_advisory_action(
                        "Plugin description claims very broad applicability."
                    ),
                ))
                break

    # ── 7. Missing security-relevant metadata ──────────────────────
    missing_keys = [k for k in ("name", "version", "description", "author") if not data.get(k)]
    if missing_keys:
        findings.append(Layer1Finding(
            detector="plugin_manifest_detector",
            type="PLUGIN_MISSING_METADATA",
            owasp_id="LLM03",
            severity="LOW",
            line=1,
            matched_snippet=f"missing: {missing_keys}",
            harm_category="SUPPLY_CHAIN",
            recommended_action=_advisory_action(
                f"Plugin manifest missing security-relevant metadata: {missing_keys}."
            ),
        ))

    return findings
