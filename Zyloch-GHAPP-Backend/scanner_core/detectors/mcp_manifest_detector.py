"""MCP server manifest detector.

Parses an MCP-server configuration block (the `command`, `args`, `env`,
`url` schema). Works on both:

  - Standalone `mcp.json` / `.mcp.json` files
  - Embedded `mcpServers:` blocks from plugin.json or skill frontmatter

Refs:
  - MCP spec — modelcontextprotocol.io
  - Invariant Labs MCP Tool Poisoning notification
  - CVE-2025-53773 (Copilot Chat RCE via MCP injection)
  - Prompt Security dependency-hijack disclosure
"""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Tuple

from scanner_core.helpers.models import Layer1Finding

# Suspicious launchers — covers the curl|sh / wget|sh / remote-exec class.
# Deliberately excludes `node`, `python`, `deno` (legitimate MCP server runtimes).
RISKY_COMMAND_RE = re.compile(
    r"^(?:curl|wget|fetch|powershell|pwsh|iwr|iex|sudo|bash|sh|zsh|eval|exec)$",
    re.IGNORECASE,
)

# Args patterns indicating risk.
RISKY_ARG_PATTERNS = [
    (re.compile(r"\b-fsSL?\b.*https?://", re.IGNORECASE),
     "Remote download via curl -fsSL (`curl … | sh` class)"),
    (re.compile(r"\|\s*(?:bash|sh|zsh|python)\b", re.IGNORECASE),
     "Pipe-to-shell pattern"),
    (re.compile(r"--?(?:extra-)?index-url\b", re.IGNORECASE),
     "Custom pip index URL (dependency-hijack signature)"),
    (re.compile(r"\b(?:eval|exec)\s*\(", re.IGNORECASE),
     "eval() / exec() in args"),
    (re.compile(r"https?://(?:raw\.githubusercontent\.com|gist\.|pastebin\.|paste\.ee)", re.IGNORECASE),
     "Remote raw-content URL"),
]

# Env-var values that should never appear in MCP configuration.
RISKY_ENV_VALUES = [
    (re.compile(r"~?/\.aws/", re.IGNORECASE), "AWS credentials path"),
    (re.compile(r"~?/\.ssh/", re.IGNORECASE), "SSH key path"),
    (re.compile(r"~?/\.kube/", re.IGNORECASE), "Kubernetes config path"),
    (re.compile(r"~?/\.netrc\b", re.IGNORECASE), ".netrc path"),
    (re.compile(r"\.env\b", re.IGNORECASE), ".env file path"),
    (re.compile(r"/etc/(?:passwd|shadow)", re.IGNORECASE), "System credential file"),
]

# Specific env var names that, if MENTIONED in values (not just keys), are risky.
SENSITIVE_ENV_KEYS = {"ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GITHUB_TOKEN",
                       "AWS_SECRET_ACCESS_KEY", "AWS_ACCESS_KEY_ID"}


def _advisory_action(summary: str) -> str:
    return (
        f"MCP server entry: {summary}. ADVISORY — review whether the declared command "
        "matches the plugin's stated purpose; Layer 2 will judge intent."
    )


def detect_server_entry(
    server_name: str, server: Dict[str, Any], *, source: str = "mcp_manifest_detector",
    base_line: Optional[int] = None,
) -> List[Layer1Finding]:
    """Inspect a single MCP server config block.

    Args:
      server_name: the key under `mcpServers` (e.g. "fs-server")
      server: the dict containing `command`, `args`, `env`, optionally `url`
      source: the detector name to record on emitted findings
      base_line: approximate line number for the server entry (best-effort)
    """
    findings: List[Layer1Finding] = []
    if not isinstance(server, dict):
        return findings

    command = server.get("command")
    args = server.get("args", [])
    env = server.get("env", {})
    url = server.get("url")

    if isinstance(command, str) and RISKY_COMMAND_RE.match(command.strip()):
        findings.append(Layer1Finding(
            detector=source,
            type="MCP_RISKY_LAUNCHER",
            owasp_id="LLM05",
            severity="LOW",
            line=base_line,
            matched_snippet=f'"{server_name}".command = {command!r}',
            harm_category="PRIVILEGE_ESCALATION",
            recommended_action=_advisory_action(
                f"server {server_name!r} uses a remote-exec-class launcher ({command})"
            ),
        ))

    arg_blob = " ".join(str(a) for a in args) if isinstance(args, list) else str(args)
    for pattern, desc in RISKY_ARG_PATTERNS:
        if pattern.search(arg_blob):
            findings.append(Layer1Finding(
                detector=source,
                type="MCP_RISKY_ARGS",
                owasp_id="LLM03",
                severity="LOW",
                line=base_line,
                matched_snippet=f'"{server_name}".args = {arg_blob[:120]!r}',
                harm_category="SUPPLY_CHAIN",
                recommended_action=_advisory_action(
                    f"server {server_name!r} args contain {desc.lower()}"
                ),
            ))
            break  # one finding per server entry is enough

    if isinstance(env, dict):
        for key, value in env.items():
            if not isinstance(value, str):
                continue
            for pattern, desc in RISKY_ENV_VALUES:
                if pattern.search(value):
                    findings.append(Layer1Finding(
                        detector=source,
                        type="MCP_RISKY_ENV",
                        owasp_id="LLM02",
                        severity="LOW",
                        line=base_line,
                        matched_snippet=f'"{server_name}".env.{key} = {value[:80]!r}',
                        harm_category="EXFILTRATION",
                        recommended_action=_advisory_action(
                            f"server {server_name!r} env passes {desc.lower()} ({key})"
                        ),
                    ))
                    break

    if isinstance(url, str) and re.search(r"^https?://", url):
        # Untrusted HTTP MCP endpoint
        if not re.search(r"^https://(?:localhost|127\.0\.0\.1|.*\.anthropic\.com)", url):
            findings.append(Layer1Finding(
                detector=source,
                type="MCP_REMOTE_URL",
                owasp_id="LLM03",
                severity="LOW",
                line=base_line,
                matched_snippet=f'"{server_name}".url = {url[:120]!r}',
                harm_category="SUPPLY_CHAIN",
                recommended_action=_advisory_action(
                    f"server {server_name!r} points at remote URL {url}"
                ),
            ))

    return findings


def _parse_json_keep_line(text: str) -> Tuple[Optional[Dict[str, Any]], Dict[str, int]]:
    """Parse JSON and return (data, key_line_map).

    The line map gives approximate line numbers for the top-level server keys
    so findings carry usable locations.
    """
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return None, {}

    key_lines: Dict[str, int] = {}
    # Find `mcpServers` block if present
    m = re.search(r'"mcpServers"\s*:\s*\{', text)
    if m:
        block_start = m.end()
        # Walk through the block tallying braces to find the closing `}`
        depth = 1
        i = block_start
        while i < len(text) and depth > 0:
            c = text[i]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
            i += 1
        block = text[block_start:i - 1] if depth == 0 else text[block_start:]
        for sm in re.finditer(r'"([^"]+)"\s*:\s*\{', block):
            line_no = text.count("\n", 0, block_start + sm.start()) + 1
            key_lines[sm.group(1)] = line_no
    return data if isinstance(data, dict) else None, key_lines


def detect_mcp_json(text: str) -> List[Layer1Finding]:
    """Top-level entry for a standalone mcp.json file."""
    data, key_lines = _parse_json_keep_line(text)
    if data is None:
        return []

    servers = data.get("mcpServers") or data.get("servers") or {}
    if not isinstance(servers, dict):
        return []

    findings: List[Layer1Finding] = []
    for name, server in servers.items():
        if not isinstance(server, dict):
            continue
        findings.extend(detect_server_entry(
            name, server,
            source="mcp_manifest_detector",
            base_line=key_lines.get(name),
        ))
    return findings


def detect_embedded_servers(
    servers: Dict[str, Any], *, source: str, base_line: Optional[int] = None,
) -> List[Layer1Finding]:
    """For mcpServers blocks embedded in plugin.json or skill frontmatter."""
    findings: List[Layer1Finding] = []
    if not isinstance(servers, dict):
        return findings
    for name, server in servers.items():
        if not isinstance(server, dict):
            continue
        findings.extend(detect_server_entry(
            name, server, source=source, base_line=base_line,
        ))
    return findings
