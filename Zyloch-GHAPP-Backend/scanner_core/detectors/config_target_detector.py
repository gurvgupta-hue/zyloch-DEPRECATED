"""Trust-elevation config-target detector.

Detects when a skill body or bundled script reads/writes/installs into
the host agent's trust-elevation surface. These are advisories — a real
DevOps skill *might* legitimately touch some of these paths, so Layer 2
gates the final severity.

Targets cover the disclosed exploit surface:
  - CVE-2025-53773 (Copilot Chat RCE via .vscode/settings.json autoApprove)
  - PromptArmor — Hijacking Claude Code via Marketplace Plugins (settings.local.json)
  - Prompt Security — Dependency Hijack via pip --index-url
  - Anthropic Claude Code Security docs (writes to .git, .claude, .vscode, .idea, .husky)

Refs:
  https://embracethered.com/blog/posts/2025/github-copilot-remote-code-execution-via-prompt-injection/
  https://www.promptarmor.com/resources/hijacking-claude-code-via-injected-marketplace-plugins
  https://prompt.security/blog/when-your-plugin-starts-picking-your-dependencies-marketplace-skills-and-dependency-hijack-in-claude-code
  https://code.claude.com/docs/en/security
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Pattern

from scanner_core.helpers.models import HarmCategory, Layer1Finding


@dataclass(frozen=True)
class _Rule:
    type: str
    pattern: Pattern[str]
    owasp_id: str
    harm: HarmCategory
    description: str


def _re(s: str) -> Pattern[str]:
    return re.compile(s, re.IGNORECASE)


# ── Trust-elevation file paths ─────────────────────────────────────────
PATH_RULES: List[_Rule] = [
    _Rule("CONFIG_TARGET_VSCODE_SETTINGS",
          _re(r"\.vscode/(settings|tasks|launch|mcp)\.json"),
          "LLM06", "PRIVILEGE_ESCALATION",
          ".vscode config (auto-approve / task-execution trust surface)"),
    _Rule("CONFIG_TARGET_CLAUDE_SETTINGS",
          _re(r"(\.claude/settings\.(local\.)?json|~?/\.claude/(settings|mcp|skills)/)"),
          "LLM06", "PRIVILEGE_ESCALATION",
          "Claude Code settings / skills directory"),
    _Rule("CONFIG_TARGET_CURSOR_RULES",
          _re(r"(\.cursorrules\b|\.cursor/(rules|mcp\.json|settings\.json))"),
          "LLM06", "PRIVILEGE_ESCALATION",
          "Cursor rules / MCP / settings"),
    _Rule("CONFIG_TARGET_COPILOT_INSTRUCTIONS",
          _re(r"\.github/copilot-instructions\.md"),
          "LLM06", "PRIVILEGE_ESCALATION",
          "GitHub Copilot instructions file"),
    _Rule("CONFIG_TARGET_AGENTS_MD",
          _re(r"(^|[\s/])AGENTS\.md\b"),
          "LLM06", "PRIVILEGE_ESCALATION",
          "AGENTS.md (nearest-file precedence may shadow root rules)"),
    _Rule("CONFIG_TARGET_MCP_JSON",
          _re(r"(^|[\s/])mcp\.json\b"),
          "LLM03", "SUPPLY_CHAIN",
          "MCP server manifest (arbitrary binary registration)"),
    _Rule("CONFIG_TARGET_SECRETS",
          _re(r"(~?/\.aws/credentials|~?/\.aws/config|~?/\.ssh/|~?/\.kube/config|"
              r"~?/\.config/gh/hosts\.yml|/etc/passwd|/etc/shadow|"
              r"\bANTHROPIC_API_KEY\b|\bOPENAI_API_KEY\b|\bGITHUB_TOKEN\b|"
              r"~?/\.netrc\b|~?/\.git-credentials\b)"),
          "LLM02", "EXFILTRATION",
          "Long-lived credential / secret location"),
    _Rule("CONFIG_TARGET_ENV_FILE",
          _re(r"(^|[\s/(])(\.env(\.local|\.production|\.development)?)(\b|[\s\"',)])"),
          "LLM02", "EXFILTRATION",
          ".env file (project secrets)"),
    _Rule("CONFIG_TARGET_GIT_INTERNALS",
          _re(r"\.git/(hooks/|config\b|info/exclude)"),
          "LLM06", "PRIVILEGE_ESCALATION",
          ".git internals (hooks / config — supply-chain reach into commits)"),
    _Rule("CONFIG_TARGET_HUSKY",
          _re(r"\.husky/"),
          "LLM06", "PRIVILEGE_ESCALATION",
          "husky git hooks directory"),
]


# ── Auto-approve / permission-bypass flag strings ─────────────────────
FLAG_RULES: List[_Rule] = [
    _Rule("AUTOAPPROVE_VSCODE",
          _re(r'"chat\.tools\.autoApprove"\s*:\s*true'),
          "LLM06", "PRIVILEGE_ESCALATION",
          "VS Code Copilot Chat auto-approve flag (CVE-2025-53773 vector)"),
    _Rule("AUTOAPPROVE_CLI_FLAG",
          _re(r"--dangerously-skip-permissions\b"),
          "LLM06", "PRIVILEGE_ESCALATION",
          "Claude Code --dangerously-skip-permissions CLI flag"),
    _Rule("AUTOAPPROVE_BYPASS_STRING",
          _re(r'\b(bypassPermissions|acceptEdits|permissionMode)\s*[:=]\s*["\']?(bypass|accept|allow|auto|yes|true)'),
          "LLM06", "PRIVILEGE_ESCALATION",
          "Permission-bypass mode declaration"),
    _Rule("AUTOAPPROVE_PERMISSIONS_ALLOW",
          _re(r'"permissions"\s*:\s*\{[^}]*"allow"\s*:\s*\['),
          "LLM06", "PRIVILEGE_ESCALATION",
          "Permission allowlist mutation"),
]


# ── Dependency-hijack signatures ───────────────────────────────────────
DEPENDENCY_RULES: List[_Rule] = [
    _Rule("DEP_PIP_INDEX_OVERRIDE",
          _re(r"\bpip\s+(install|config\s+set).*?(--(extra-)?index-url|global\.index-url)\b"),
          "LLM03", "SUPPLY_CHAIN",
          "pip index URL override (Prompt Security dependency-hijack signature)"),
    _Rule("DEP_PIP_INDEX_CONFIG",
          _re(r"\bpip\s+config\s+set\s+global\.index-url\b"),
          "LLM03", "SUPPLY_CHAIN",
          "pip global index URL persisted to config"),
    _Rule("DEP_NPM_REGISTRY_OVERRIDE",
          _re(r"\bnpm\s+(install|config\s+set).*?(--registry=|registry\s+)\S+"),
          "LLM03", "SUPPLY_CHAIN",
          "npm registry override"),
    _Rule("DEP_CURL_PIPE_SHELL",
          _re(r"\bcurl\s+(-fsSL?\s+)?\S+\s*\|\s*(bash|sh|zsh|python|node)\b"),
          "LLM05", "PRIVILEGE_ESCALATION",
          "`curl … | sh` remote-script execution"),
    _Rule("DEP_WGET_PIPE_SHELL",
          _re(r"\bwget\s+\S+\s*-O-\s*\|\s*(bash|sh|zsh)\b"),
          "LLM05", "PRIVILEGE_ESCALATION",
          "`wget … | sh` remote-script execution"),
]


ALL_RULES = PATH_RULES + FLAG_RULES + DEPENDENCY_RULES


def _advisory_action(description: str) -> str:
    return (
        f"Skill references {description}. This is a trust-elevation surface. "
        "ADVISORY — not necessarily malicious if the skill's stated purpose covers this; "
        "Layer 2 will judge intent."
    )


def detect(text: str) -> List[Layer1Finding]:
    findings: List[Layer1Finding] = []
    if not text:
        return findings

    seen_types: set[str] = set()
    for rule in ALL_RULES:
        for m in rule.pattern.finditer(text):
            if rule.type in seen_types:
                break
            seen_types.add(rule.type)
            line = text.count("\n", 0, m.start()) + 1
            snip = text[max(0, m.start() - 20) : m.end() + 20].strip()[:160].replace("\n", " ")
            findings.append(Layer1Finding(
                detector="config_target_detector",
                type=rule.type,
                owasp_id=rule.owasp_id,
                severity="LOW",
                line=line,
                matched_snippet=snip,
                harm_category=rule.harm,
                recommended_action=_advisory_action(rule.description),
            ))
            break

    return findings
