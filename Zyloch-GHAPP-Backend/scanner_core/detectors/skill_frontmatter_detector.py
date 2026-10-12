"""Skill-file YAML frontmatter advisory detector.

Scope: SKILL.md, .claude/agents/*.md, CLAUDE.md, .cursorrules, subagent
and plugin manifests. Detects trust-elevation declarations:

  - tools: "*"            (wildcard tool grant)
  - tools omitted          (subagent inherits all parent tools)
  - permissionMode: bypassPermissions | acceptEdits
  - embedded mcpServers: blocks (skill ships its own MCP server)
  - hooks: PreToolUse / PrePrompt / Stop running shell
  - broad-trigger descriptions ("use whenever the user asks about anything…")
  - name homoglyphs ("сlaude", "anthr0pic" — Cyrillic/digit lookalikes)

All findings are emitted as LOW severity ADVISORIES. The Layer 2 LLM
analyzer judges whether each declaration is justified by the skill's
stated purpose and can escalate severity in its own finding.

Refs:
  Anthropic Agent Skills overview · https://platform.claude.com/docs/en/agents-and-tools/agent-skills/overview
  Anthropic Create custom subagents · https://code.claude.com/docs/en/sub-agents
  Pillar — Rules File Backdoor · https://www.pillar.security/blog/new-vulnerability-in-github-copilot-and-cursor-how-hackers-can-weaponize-code-agents
  PromptArmor — Hijacking Claude Code · https://www.promptarmor.com/resources/hijacking-claude-code-via-injected-marketplace-plugins
"""
from __future__ import annotations

import re
import unicodedata
from typing import Any, Dict, List, Optional

import yaml

from scanner_core.helpers.models import Layer1Finding


FRONTMATTER_RE = re.compile(r"\A---\n(.*?)\n---\n", re.DOTALL)

BYPASS_VALUES = {"bypasspermissions", "acceptedits", "skip", "allow", "auto", "yolo"}

DANGEROUS_HOOK_KEYS = {
    "pretooluse", "preprompt", "stop", "posttooluse", "configchange",
    "subagentstart", "subagentstop",
}

# Heuristic: descriptions that try to win Level-1 routing for everything.
BROAD_TRIGGER_PATTERNS = [
    re.compile(r"\b(use|invoke|apply|run)\b.{0,40}\b(whenever|any time|always|every (time|request))\b", re.I),
    re.compile(r"\b(for|with) (any|every|all) (request|question|prompt|task|input)\b", re.I),
    re.compile(r"\b(general(-?| )purpose|catch[ -]?all|do anything)\b", re.I),
    re.compile(r"\b(replaces|supersedes|overrides) (all |other )?(skills|tools|prompts)\b", re.I),
]

# Reserved root-words Claude rejects in skill names. Homoglyph variants are not
# rejected upstream — we flag them ourselves.
RESERVED_NAME_ROOTS = ["anthropic", "claude"]

LATIN_LETTERS = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")


def _parse_frontmatter(text: str) -> Optional[Dict[str, Any]]:
    m = FRONTMATTER_RE.match(text)
    if not m:
        return None
    try:
        data = yaml.safe_load(m.group(1))
    except yaml.YAMLError:
        return None
    return data if isinstance(data, dict) else None


def _frontmatter_line(text: str, key: str) -> Optional[int]:
    """Return the 1-based line number of `key:` within the frontmatter block."""
    m = FRONTMATTER_RE.match(text)
    if not m:
        return None
    body = m.group(1).splitlines()
    pattern = re.compile(rf"^\s*{re.escape(key)}\s*:", re.IGNORECASE)
    for i, line in enumerate(body, start=2):  # +1 for opening `---`, +1 because line 1 is `---`
        if pattern.search(line):
            return i
    return None


def _normalized_name(s: str) -> str:
    """NFKC + map common confusables to ASCII for homoglyph comparison."""
    normalized = unicodedata.normalize("NFKC", s)
    # quick confusable swaps for the two reserved roots we care about
    swaps = str.maketrans({
        "а": "a", "А": "A",  # Cyrillic
        "е": "e", "Е": "E",
        "о": "o", "О": "O",
        "с": "c", "С": "C",
        "р": "p", "Р": "P",
        "і": "i", "І": "I",
        "ѕ": "s", "Ѕ": "S",
        "ԛ": "q", "Ԛ": "Q",
        "ʟ": "L", "ɴ": "N",
        "0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t",
    })
    return normalized.translate(swaps).lower()


def _looks_like_reserved(name: str) -> Optional[str]:
    if not name:
        return None
    normalized = _normalized_name(name)
    raw_lower = name.lower()
    for root in RESERVED_NAME_ROOTS:
        if root in normalized and root not in raw_lower:
            return root
    return None


def _flatten_yaml_string(value: Any) -> str:
    """Render a yaml value compactly for snippet display."""
    try:
        return yaml.safe_dump(value, default_flow_style=True).strip()
    except Exception:
        return str(value)


def detect(text: str) -> List[Layer1Finding]:
    fm = _parse_frontmatter(text)
    if fm is None:
        return []

    findings: List[Layer1Finding] = []
    advisory_action_suffix = (
        " — ADVISORY (not necessarily malicious). Verify this matches the skill's "
        "stated purpose; Layer 2 will judge intent."
    )

    # 1. tools: '*' or wildcard list
    tools = fm.get("tools")
    if isinstance(tools, str) and tools.strip() == "*":
        findings.append(Layer1Finding(
            detector="skill_frontmatter_detector",
            type="FRONTMATTER_WILDCARD_TOOLS",
            owasp_id="LLM06",
            severity="LOW",
            line=_frontmatter_line(text, "tools"),
            matched_snippet=f"tools: {tools!r}",
            harm_category="PRIVILEGE_ESCALATION",
            recommended_action="Skill requests wildcard tool access (`tools: '*'`)." + advisory_action_suffix,
        ))
    elif isinstance(tools, list) and any(
        isinstance(t, str) and t.strip() in {"*", "all"} for t in tools
    ):
        findings.append(Layer1Finding(
            detector="skill_frontmatter_detector",
            type="FRONTMATTER_WILDCARD_TOOLS",
            owasp_id="LLM06",
            severity="LOW",
            line=_frontmatter_line(text, "tools"),
            matched_snippet=f"tools: {_flatten_yaml_string(tools)[:120]}",
            harm_category="PRIVILEGE_ESCALATION",
            recommended_action="Skill requests wildcard tool access in tools list." + advisory_action_suffix,
        ))

    # 2. permissionMode: bypassPermissions / acceptEdits
    pm = fm.get("permissionMode") or fm.get("permission_mode")
    if isinstance(pm, str) and pm.strip().lower() in BYPASS_VALUES:
        findings.append(Layer1Finding(
            detector="skill_frontmatter_detector",
            type="FRONTMATTER_BYPASS_PERMISSIONS",
            owasp_id="LLM06",
            severity="LOW",
            line=_frontmatter_line(text, "permissionMode") or _frontmatter_line(text, "permission_mode"),
            matched_snippet=f"permissionMode: {pm!r}",
            harm_category="PRIVILEGE_ESCALATION",
            recommended_action=(
                f"Skill sets permissionMode={pm!r}, which skips approval prompts when invoking tools."
                + advisory_action_suffix
            ),
        ))

    # 3. embedded mcpServers
    mcp = fm.get("mcpServers") or fm.get("mcp_servers")
    if isinstance(mcp, dict) and mcp:
        names = ", ".join(list(mcp.keys())[:5])
        findings.append(Layer1Finding(
            detector="skill_frontmatter_detector",
            type="FRONTMATTER_EMBEDDED_MCP_SERVER",
            owasp_id="LLM03",
            severity="LOW",
            line=_frontmatter_line(text, "mcpServers") or _frontmatter_line(text, "mcp_servers"),
            matched_snippet=f"mcpServers: [{names}]",
            harm_category="SUPPLY_CHAIN",
            recommended_action=(
                f"Skill ships its own MCP server definition(s): {names}. MCP servers run arbitrary code with"
                " agent privileges." + advisory_action_suffix
            ),
        ))

    # 4. hooks declaring shell-running entries
    hooks = fm.get("hooks")
    if isinstance(hooks, dict) and hooks:
        flagged_keys = []
        for key, value in hooks.items():
            if not isinstance(key, str):
                continue
            if key.lower().replace("_", "") in DANGEROUS_HOOK_KEYS:
                flagged_keys.append(key)
        if flagged_keys:
            findings.append(Layer1Finding(
                detector="skill_frontmatter_detector",
                type="FRONTMATTER_HOOKS_DECLARED",
                owasp_id="LLM06",
                severity="LOW",
                line=_frontmatter_line(text, "hooks"),
                matched_snippet=f"hooks: [{', '.join(flagged_keys)}]",
                harm_category="PRIVILEGE_ESCALATION",
                recommended_action=(
                    f"Skill declares lifecycle hooks ({', '.join(flagged_keys)}) that run on every"
                    " tool invocation." + advisory_action_suffix
                ),
            ))

    # 5. broad-trigger description (auto-load routing race)
    desc = fm.get("description")
    if isinstance(desc, str) and desc.strip():
        for pat in BROAD_TRIGGER_PATTERNS:
            m = pat.search(desc)
            if m:
                findings.append(Layer1Finding(
                    detector="skill_frontmatter_detector",
                    type="FRONTMATTER_BROAD_TRIGGER_DESCRIPTION",
                    owasp_id="LLM01",
                    severity="LOW",
                    line=_frontmatter_line(text, "description"),
                    matched_snippet=desc.strip()[:160],
                    harm_category="SOCIAL_ENGINEERING",
                    recommended_action=(
                        "Description claims very broad applicability — this can win the skill auto-load"
                        " routing race. Verify the body actually does what the description claims."
                        + advisory_action_suffix
                    ),
                ))
                break

    # 6. name homoglyph evasion of reserved words
    name = fm.get("name")
    if isinstance(name, str):
        spoofed = _looks_like_reserved(name)
        if spoofed:
            findings.append(Layer1Finding(
                detector="skill_frontmatter_detector",
                type="FRONTMATTER_NAME_HOMOGLYPH",
                owasp_id="LLM01",
                severity="LOW",
                line=_frontmatter_line(text, "name"),
                matched_snippet=f"name: {name!r}",
                harm_category="SOCIAL_ENGINEERING",
                recommended_action=(
                    f"Skill name visually resembles reserved root {spoofed!r} via Unicode confusables."
                    " Anthropic's reserved-name check is not confusable-aware." + advisory_action_suffix
                ),
            ))

    return findings
