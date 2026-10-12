"""
CIS Controls v8.1 AI Agents Companion Guide Scanner

Scans AI-agent repositories for compliance with CIS Critical Security Controls
v8.1 as interpreted through the lens of autonomous and semi-autonomous AI agent
architectures.  The guide (published April 2026) maps each of the 18 CIS
Controls to the unique operational footprint of agent systems — spanning
identity layers, endpoint execution environments, knowledge stores, integration
pipelines, and monitoring.

Reference:
  https://www.cisecurity.org/insights/white-papers/controls-v8-1-ai-agents-companion-guide

Targets scanned
  Code files      : .py  .js  .ts  .jsx  .tsx
  Config files    : .json  .yaml  .yml  .toml  .ini  .cfg
  Dependency files: requirements*.txt  pyproject.toml  setup.py  setup.cfg
                    package.json  Pipfile
  Container files : Dockerfile*  docker-compose*.yml
  Env templates   : *.env.example  *.env.template

ScanFinding field mapping:
  policy   — "cis_agent:<safeguard_id>:<rule_slug>"
  severity — ScanSeverity enum
  description — human-readable text with embedded CIS safeguard ID
  code     — CIS safeguard ID  (e.g. "CIS-6.1")
  url      — canonical CIS Controls v8.1 AI Agents guide URL
  column   — CIS control group title (e.g. "Access Control Management")
  deny     — ["CIS Control <n>: <title>"]
  match    — matched snippet (capped at 500 chars)
  file     — repo-relative path of the scanned file
  line     — 1-based line number as string (None for file-level findings)
"""
from __future__ import annotations

import json as _json
import os
import re
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from scanner_core.base_scanner import (
    BaseScanner,
    ScanFinding,
    ScanRequest,
    ScanResponse,
    ScanResult,
    ScanSeverity,
    ScanStatus,
)
from scanner_core.helpers.scoring_engine import OPABasedScoreAdapter
from scanner_core.logging_config import get_scanner_logger

logger = get_scanner_logger()


# CIS Controls v8.1 safeguard registry
# Used to enrich findings with control metadata.

_CIS_SAFEGUARDS: Dict[str, Dict[str, str]] = {
    # Control 1 — Enterprise Asset Management
    "CIS-1.1": {
        "control": "1",
        "title": "Enterprise Asset Management",
        "safeguard": "Establish and Maintain Detailed Enterprise Asset Inventory",
    },
    # Control 2 — Software Asset Management
    "CIS-2.2": {
        "control": "2",
        "title": "Software Asset Management",
        "safeguard": "Ensure Authorized Software is Currently Supported",
    },
    "CIS-2.3": {
        "control": "2",
        "title": "Software Asset Management",
        "safeguard": "Address Unauthorized Software",
    },
    # Control 3 — Data Protection
    "CIS-3.1": {
        "control": "3",
        "title": "Data Protection",
        "safeguard": "Establish and Maintain a Data Management Process",
    },
    "CIS-3.3": {
        "control": "3",
        "title": "Data Protection",
        "safeguard": "Configure Data Access Control Lists",
    },
    "CIS-3.11": {
        "control": "3",
        "title": "Data Protection",
        "safeguard": "Encrypt Sensitive Data at Rest",
    },
    # Control 4 — Secure Configuration
    "CIS-4.1": {
        "control": "4",
        "title": "Secure Configuration",
        "safeguard": "Establish and Maintain a Secure Configuration Process",
    },
    "CIS-4.6": {
        "control": "4",
        "title": "Secure Configuration",
        "safeguard": "Securely Manage Enterprise Assets and Software",
    },
    # Control 5 — Account Management
    "CIS-5.2": {
        "control": "5",
        "title": "Account Management",
        "safeguard": "Use Unique Passwords",
    },
    "CIS-5.4": {
        "control": "5",
        "title": "Account Management",
        "safeguard": "Restrict Administrator Privileges to Dedicated Administrator Accounts",
    },
    # Control 6 — Access Control Management
    "CIS-6.1": {
        "control": "6",
        "title": "Access Control Management",
        "safeguard": "Establish an Access Granting Process",
    },
    "CIS-6.3": {
        "control": "6",
        "title": "Access Control Management",
        "safeguard": "Require MFA for Externally-Exposed Applications",
    },
    "CIS-6.8": {
        "control": "6",
        "title": "Access Control Management",
        "safeguard": "Define and Maintain Role-Based Access Control",
    },
    # Control 7 — Continuous Vulnerability Management
    "CIS-7.1": {
        "control": "7",
        "title": "Continuous Vulnerability Management",
        "safeguard": "Establish and Maintain a Vulnerability Management Process",
    },
    "CIS-7.5": {
        "control": "7",
        "title": "Continuous Vulnerability Management",
        "safeguard": "Perform Automated Vulnerability Scans of Internal Enterprise Assets",
    },
    # Control 8 — Audit Log Management
    "CIS-8.1": {
        "control": "8",
        "title": "Audit Log Management",
        "safeguard": "Establish and Maintain an Audit Log Management Process",
    },
    "CIS-8.2": {
        "control": "8",
        "title": "Audit Log Management",
        "safeguard": "Collect Audit Logs",
    },
    "CIS-8.5": {
        "control": "8",
        "title": "Audit Log Management",
        "safeguard": "Collect Detailed Audit Logs",
    },
    # Control 10 — Malware Defenses (prompt injection as malicious input)
    "CIS-10.1": {
        "control": "10",
        "title": "Malware Defenses",
        "safeguard": "Deploy and Maintain Anti-Malware Software",
    },
    "CIS-10.2": {
        "control": "10",
        "title": "Malware Defenses",
        "safeguard": "Configure Automatic Anti-Malware Signature Updates",
    },
    # Control 12 — Network Infrastructure Management
    "CIS-12.2": {
        "control": "12",
        "title": "Network Infrastructure Management",
        "safeguard": "Establish and Maintain a Secure Network Architecture",
    },
    "CIS-12.6": {
        "control": "12",
        "title": "Network Infrastructure Management",
        "safeguard": "Use Secure Network Management and Communication Protocols",
    },
    # Control 13 — Network Monitoring and Defense
    "CIS-13.1": {
        "control": "13",
        "title": "Network Monitoring and Defense",
        "safeguard": "Centralize Security Event Alerting",
    },
    # Control 16 — Application Software Security
    "CIS-16.1": {
        "control": "16",
        "title": "Application Software Security",
        "safeguard": "Establish and Maintain a Secure Application Development Process",
    },
    "CIS-16.7": {
        "control": "16",
        "title": "Application Software Security",
        "safeguard": "Use Standard Hardening Configuration Templates",
    },
    # Control 17 — Incident Response Management
    "CIS-17.4": {
        "control": "17",
        "title": "Incident Response Management",
        "safeguard": "Establish and Maintain an Incident Response Process",
    },
}


# File-discovery constants
_CODE_EXTS: Set[str] = {".py", ".js", ".ts", ".jsx", ".tsx"}
_CONFIG_EXTS: Set[str] = {".json", ".yaml", ".yml", ".toml", ".ini", ".cfg"}

# Exact lower-case names treated as dependency files
_DEP_FILE_NAMES: Set[str] = {
    "requirements.txt",
    "requirements-dev.txt",
    "requirements_dev.txt",
    "requirements-test.txt",
    "pyproject.toml",
    "setup.py",
    "setup.cfg",
    "package.json",
    "pipfile",
}

_SKIP_DIRS: Set[str] = {
    ".git", "__pycache__", "node_modules", ".venv", "venv",
    "site-packages", ".mypy_cache", ".pytest_cache",
    "dist", "build", "coverage", ".tox", ".eggs",
}

_MAX_FILE_BYTES = 512 * 1024  # 512 KB — skip oversized generated files

def _is_scannable(path: Path) -> bool:
    """Return True for files the CIS agent scanner processes."""
    name = path.name.lower()

    if name in _DEP_FILE_NAMES:
        return True

    # Dockerfile / docker-compose
    if name.startswith("dockerfile") or name.startswith("docker-compose"):
        return True

    # .env templates (skip real .env files that may contain live secrets)
    if name.endswith(".env.example") or name.endswith(".env.template"):
        return True

    # requirements-*.txt variants beyond the exact names above
    if re.match(r"requirements[-_].*\.txt$", name):
        return True

    return path.suffix.lower() in (_CODE_EXTS | _CONFIG_EXTS)


def _discover_files(repo_path: str) -> List[Path]:
    root = Path(repo_path)
    found: List[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for filename in filenames:
            candidate = Path(dirpath) / filename
            if _is_scannable(candidate):
                try:
                    if candidate.stat().st_size <= _MAX_FILE_BYTES:
                        found.append(candidate)
                except OSError:
                    pass
    return found

# AI/ML package registries used for dependency checks
_AI_PY_PACKAGES: Set[str] = {
    "openai", "anthropic", "langchain", "langchain_core", "langchain_community",
    "langchain_openai", "langchain_anthropic", "langchain_google_genai",
    "llama_index", "llamaindex", "transformers", "huggingface_hub",
    "google_generativeai", "google_genai", "cohere", "mistralai", "groq",
    "together", "replicate", "openai_agents", "pydantic_ai", "crewai",
    "autogen", "pyautogen", "semantic_kernel", "haystack_ai",
    "litellm", "instructor", "guidance", "dspy", "chainlit",
    "langfuse", "agentops", "phoenix", "arize",
}

_AI_NPM_PACKAGES: Set[str] = {
    "openai", "@anthropic-ai/sdk", "langchain", "@langchain/core",
    "@langchain/openai", "@langchain/anthropic", "llamaindex",
    "ai", "@vercel/ai", "cohere-ai", "@google/generative-ai",
    "groq-sdk", "mistralai", "together-ai", "@mistralai/mistralai",
}

# Rule type aliases
_Rule = Tuple[str, ScanSeverity, re.Pattern, str]  # (cis_id, severity, pattern, description)

# Regex rule sets — all applied line-by-line

# ── CIS-5.2 — Hardcoded LLM / AI API credentials ───────────────────────────
_HARDCODED_KEY_RULES: List[_Rule] = [
    (
        "CIS-5.2", ScanSeverity.CRITICAL,
        re.compile(
            r"""(?:openai|anthropic|cohere|mistral|gemini|groq|huggingface|together)"""
            r"""[_\-]?(?:api[_\-]?key|secret)[^\w]*[=:]\s*['"][A-Za-z0-9_\-]{20,}['"]""",
            re.IGNORECASE,
        ),
        "Hardcoded LLM API key in source — store credentials in environment variables (CIS-5.2)",
    ),
    (
        "CIS-5.2", ScanSeverity.CRITICAL,
        re.compile(
            r"""(?:api_key|apikey|api_secret|access_token)\s*=\s*['"][A-Za-z0-9_\-\.]{20,}['"]""",
            re.IGNORECASE,
        ),
        "Hardcoded API credential assigned in code — use environment variables (CIS-5.2)",
    ),
    (
        "CIS-5.2", ScanSeverity.HIGH,
        re.compile(
            r"""(?:OPENAI_API_KEY|ANTHROPIC_API_KEY|COHERE_API_KEY|GOOGLE_API_KEY)"""
            r"""\s*=\s*['"][A-Za-z0-9_\-]{10,}['"]""",
        ),
        "LLM API key hardcoded as a string literal — use a secrets manager (CIS-5.2)",
    ),
]

# ── CIS-12.6 — SSL/TLS verification disabled ────────────────────────────────
_SSL_RULES: List[_Rule] = [
    (
        "CIS-12.6", ScanSeverity.HIGH,
        re.compile(r"""verify\s*=\s*False""", re.IGNORECASE),
        "SSL certificate verification disabled on HTTP request — agents must verify TLS (CIS-12.6)",
    ),
    (
        "CIS-12.6", ScanSeverity.HIGH,
        re.compile(r"""ssl_verify\s*=\s*(?:False|0|'false'|\"false\")""", re.IGNORECASE),
        "SSL verification explicitly disabled — agent network calls must use verified TLS (CIS-12.6)",
    ),
    (
        "CIS-12.6", ScanSeverity.MEDIUM,
        re.compile(r"""InsecureRequestWarning|urllib3\.disable_warnings""", re.IGNORECASE),
        "TLS warning suppression detected — this masks insecure agent network calls (CIS-12.6)",
    ),
]

# ── CIS-16.7 — Dynamic code execution with LLM-generated content ────────────
_EXEC_RULES: List[_Rule] = [
    (
        "CIS-16.7", ScanSeverity.CRITICAL,
        re.compile(
            r"""\beval\s*\(\s*(?:completion|response|output|result|answer|text|content|llm|agent)\b""",
            re.IGNORECASE,
        ),
        "eval() called with potential LLM-generated content — dangerous code execution (CIS-16.7)",
    ),
    (
        "CIS-16.7", ScanSeverity.CRITICAL,
        re.compile(
            r"""\bexec\s*\(\s*(?:completion|response|output|result|answer|text|content|llm|agent)\b""",
            re.IGNORECASE,
        ),
        "exec() called with potential LLM-generated content — arbitrary code execution risk (CIS-16.7)",
    ),
    (
        "CIS-16.7", ScanSeverity.HIGH,
        re.compile(
            r"""subprocess\.(?:call|run|Popen|check_output)\s*\(.*(?:completion|response|output|result|answer)\b""",
            re.IGNORECASE,
        ),
        "subprocess called with potential LLM output — validate tool inputs before execution (CIS-16.7)",
    ),
]

# ── CIS-10.1 — Prompt injection via unsanitized user input ──────────────────
_PROMPT_INJECTION_RULES: List[_Rule] = [
    (
        "CIS-10.1", ScanSeverity.HIGH,
        re.compile(
            r"""(?:f"|f'|\.format\s*\()[^'"]{0,120}"""
            r"""(?:user_input|user_message|user_query|raw_input|untrusted|external_input)""",
            re.IGNORECASE,
        ),
        "Unsanitized user input interpolated into LLM prompt — risk of prompt injection (CIS-10.1)",
    ),
    (
        "CIS-10.1", ScanSeverity.HIGH,
        re.compile(
            r"""(?:system_prompt|system_message)\s*[+=].*"""
            r"""(?:user_input|user_message|request\.body|request\.data|params\[|args\[)""",
            re.IGNORECASE,
        ),
        "User-controlled data appended to system prompt — enables prompt injection (CIS-10.1)",
    ),
    (
        "CIS-10.1", ScanSeverity.MEDIUM,
        re.compile(
            r"""(?:content|prompt)\s*[+]=?\s*.*(?:user_input|user_message|query|user_query)""",
            re.IGNORECASE,
        ),
        "User-supplied content concatenated into LLM context — sanitize before inclusion (CIS-10.1)",
    ),
]

# ── CIS-4.1 — Insecure agent configuration (debug / verbose mode) ────────────
_DEBUG_RULES: List[_Rule] = [
    (
        "CIS-4.1", ScanSeverity.MEDIUM,
        re.compile(r"""\bdebug\s*=\s*True\b""", re.IGNORECASE),
        "Debug mode enabled in agent configuration — disable in production deployments (CIS-4.1)",
    ),
    (
        "CIS-4.1", ScanSeverity.LOW,
        re.compile(r"""\bverbose\s*=\s*True\b""", re.IGNORECASE),
        "Verbose mode enabled — may expose sensitive agent data through logs (CIS-4.1)",
    ),
]

# ── CIS-8.2 — Missing structured logging (printing LLM responses) ────────────
_LOGGING_RULES: List[_Rule] = [
    (
        "CIS-8.2", ScanSeverity.MEDIUM,
        re.compile(
            r"""print\s*\(.*(?:completion|response|llm_response|agent_response|tool_result)\b""",
            re.IGNORECASE,
        ),
        "LLM response sent to print() instead of structured logger — use audit-safe logging (CIS-8.2)",
    ),
]

# ── CIS-3.3 — Sensitive data in logs / stdout ───────────────────────────────
_PII_LOG_RULES: List[_Rule] = [
    (
        "CIS-3.3", ScanSeverity.HIGH,
        re.compile(
            r"""log(?:ger|ging)?\.(?:info|debug|warning|error|critical)\s*\("""
            r""".*(?:password|passwd|secret|token|api_key|ssn|credit_card|social_security)\b""",
            re.IGNORECASE,
        ),
        "Potential PII or credential logged by agent — sanitize log output (CIS-3.3)",
    ),
    (
        "CIS-3.3", ScanSeverity.MEDIUM,
        re.compile(
            r"""print\s*\(.*(?:password|passwd|secret|token|api_key)\b""",
            re.IGNORECASE,
        ),
        "Potential credential printed to stdout — agents must not leak secrets (CIS-3.3)",
    ),
]

# ── CIS-6.1 — Overly permissive agent tool access ───────────────────────────
_PERMISSION_RULES: List[_Rule] = [
    (
        "CIS-6.1", ScanSeverity.HIGH,
        re.compile(
            r"""(?:permissions|scopes|capabilities|tools|allowed_actions)\s*[=:]\s*\[?\s*['"]?\*['"]?""",
            re.IGNORECASE,
        ),
        "Wildcard permissions granted to agent — apply least-privilege access control (CIS-6.1)",
    ),
    (
        "CIS-6.1", ScanSeverity.HIGH,
        re.compile(r"""\ballow_all\s*[=:]\s*True\b""", re.IGNORECASE),
        "allow_all flag enabled — agent must have explicit, scoped permissions (CIS-6.1)",
    ),
    (
        "CIS-6.8", ScanSeverity.HIGH,
        re.compile(
            r"""(?:human_approval|require_approval|human_in_loop|human_confirmation)\s*[=:]\s*False\b""",
            re.IGNORECASE,
        ),
        "Human-in-the-loop approval disabled for agent actions — required for high-risk operations (CIS-6.8)",
    ),
    (
        "CIS-6.1", ScanSeverity.MEDIUM,
        re.compile(
            r"""(?:filesystem|os\.system|shell|bash|cmd)\s*[=:]\s*(?:True|'enabled'|\"enabled\")""",
            re.IGNORECASE,
        ),
        "Unrestricted filesystem or shell access enabled for agent — scope to least-privilege (CIS-6.1)",
    ),
]

# ── CIS-12.2 — Unencrypted HTTP in agent code ───────────────────────────────
_HTTP_RULES: List[_Rule] = [
    (
        "CIS-12.2", ScanSeverity.HIGH,
        re.compile(
            r"""http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0|::1)[\w\-\.]+""",
            re.IGNORECASE,
        ),
        "Unencrypted HTTP endpoint in agent code — use HTTPS for all external calls (CIS-12.2)",
    ),
]

# ── CIS-13.1 — Potential SSRF via user-supplied URLs ────────────────────────
_SSRF_RULES: List[_Rule] = [
    (
        "CIS-13.1", ScanSeverity.HIGH,
        re.compile(
            r"""(?:requests?\.(?:get|post)|fetch|urllib\.request)\s*\("""
            r""".*(?:user_input|user_url|target_url|url\s*=\s*(?:request|params|args|body|data))""",
            re.IGNORECASE,
        ),
        "Potential SSRF — agent fetching user-supplied URL without validation (CIS-13.1)",
    ),
]

# ── CIS-16.1 — Unvalidated tool outputs fed back into LLM context ───────────
_TOOL_OUTPUT_RULES: List[_Rule] = [
    (
        "CIS-16.1", ScanSeverity.MEDIUM,
        re.compile(
            r"""(?:tool_result|function_result|tool_output)\s*[+]=?\s*.*messages""",
            re.IGNORECASE,
        ),
        "Tool output appended to LLM context without validation — indirect prompt injection risk (CIS-16.1)",
    ),
    (
        "CIS-16.1", ScanSeverity.MEDIUM,
        re.compile(
            r"""messages\.append\s*\(.*(?:tool_result|function_result|tool_output)""",
            re.IGNORECASE,
        ),
        "Unvalidated tool output appended to message history — validate before LLM re-injection (CIS-16.1)",
    ),
]

# Aggregate all per-line regex rule sets
_LINE_RULES: List[_Rule] = (
    _HARDCODED_KEY_RULES
    + _SSL_RULES
    + _EXEC_RULES
    + _PROMPT_INJECTION_RULES
    + _DEBUG_RULES
    + _LOGGING_RULES
    + _PII_LOG_RULES
    + _PERMISSION_RULES
    + _HTTP_RULES
    + _SSRF_RULES
    + _TOOL_OUTPUT_RULES
)

# Dependency file checks
def _check_requirements_txt(content: str, rel_path: str) -> List[ScanFinding]:
    """Flag unpinned AI/ML packages in requirements*.txt files."""
    findings: List[ScanFinding] = []
    for i, line in enumerate(content.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("-r"):
            continue
        m = re.match(r"^([A-Za-z0-9_\-\.]+)", stripped)
        if not m:
            continue
        raw_name = m.group(1)
        normalised = raw_name.lower().replace("-", "_")
        is_ai_pkg = normalised in _AI_PY_PACKAGES

        if "==" not in stripped:
            if is_ai_pkg:
                findings.append(_make_finding(
                    cis_id="CIS-7.5",
                    severity=ScanSeverity.MEDIUM,
                    description=(
                        f"AI/LLM package '{raw_name}' is not pinned to an exact version — "
                        "unpinned dependencies cannot be reliably vulnerability-scanned (CIS-7.5)"
                    ),
                    rule_slug="unpinned_ai_dependency",
                    file=rel_path,
                    line=str(i),
                    match=stripped[:200],
                ))
            else:
                findings.append(_make_finding(
                    cis_id="CIS-2.2",
                    severity=ScanSeverity.LOW,
                    description=(
                        f"Package '{raw_name}' not pinned with exact version — "
                        "use == for reproducible, auditable agent deployments (CIS-2.2)"
                    ),
                    rule_slug="unpinned_dependency",
                    file=rel_path,
                    line=str(i),
                    match=stripped[:200],
                ))
    return findings


def _check_package_json(content: str, rel_path: str) -> List[ScanFinding]:
    """Flag unpinned AI-related Node.js packages in package.json."""
    findings: List[ScanFinding] = []
    try:
        data = _json.loads(content)
    except (ValueError, TypeError):
        return findings

    all_deps: Dict[str, str] = {
        **data.get("dependencies", {}),
        **data.get("devDependencies", {}),
    }
    for pkg, version in all_deps.items():
        if not isinstance(version, str):
            continue
        is_ai_pkg = pkg.lower() in _AI_NPM_PACKAGES
        loose = version in ("*", "latest", "next") or (
            is_ai_pkg and (version.startswith("^") or version.startswith("~"))
        )
        if not loose:
            continue
        cis_id = "CIS-7.5" if is_ai_pkg else "CIS-2.2"
        findings.append(_make_finding(
            cis_id=cis_id,
            severity=ScanSeverity.MEDIUM if is_ai_pkg else ScanSeverity.LOW,
            description=(
                f"NPM package '{pkg}' uses loose version constraint '{version}' — "
                f"pin AI/LLM packages to exact versions for vulnerability management ({cis_id})"
            ),
            rule_slug="unpinned_npm_dependency",
            file=rel_path,
            line=None,
            match=f'"{pkg}": "{version}"',
        ))
    return findings


def _check_env_template(content: str, rel_path: str) -> List[ScanFinding]:
    """Flag real-looking credential values in .env.example / .env.template files."""
    findings: List[ScanFinding] = []
    _PLACEHOLDER_RE = re.compile(
        r"(?:your[_\-]|<|xxx|changeme|placeholder|todo|insert|example|xxxxxx)",
        re.IGNORECASE,
    )
    _SECRET_KEYS = ("KEY", "SECRET", "TOKEN", "PASSWORD", "CREDENTIAL", "PASSWD", "PWD")

    for i, line in enumerate(content.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        m = re.match(r"([A-Z_][A-Z0-9_]*)\s*=\s*([^\s#]{12,})", stripped, re.IGNORECASE)
        if not m:
            continue
        key, value = m.group(1), m.group(2)
        if not any(k in key.upper() for k in _SECRET_KEYS):
            continue
        if _PLACEHOLDER_RE.search(value):
            continue
        findings.append(_make_finding(
            cis_id="CIS-5.2",
            severity=ScanSeverity.HIGH,
            description=(
                f"Real-looking credential value found for '{key}' in env template — "
                "use obvious placeholder values (e.g. 'your-api-key-here') in .env.example (CIS-5.2)"
            ),
            rule_slug="credential_in_env_template",
            file=rel_path,
            line=str(i),
            match=f"{key}=***REDACTED***",
        ))
    return findings


def _check_dockerfile(content: str, rel_path: str) -> List[ScanFinding]:
    """Check Dockerfiles for CIS agent configuration violations."""
    findings: List[ScanFinding] = []
    lines = content.splitlines()
    _PLACEHOLDER_RE = re.compile(r"(?:\$\{|<|xxx|changeme|placeholder)", re.IGNORECASE)
    has_nonroot_user = False
    has_from = False

    for i, line in enumerate(lines, 1):
        stripped = line.strip()

        # CIS-5.2: Hardcoded secrets in ENV instructions
        m = re.match(
            r"ENV\s+([A-Z_]*(?:KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL)[A-Z_0-9]*)\s+(\S{10,})",
            stripped,
            re.IGNORECASE,
        )
        if m and not _PLACEHOLDER_RE.search(m.group(2)):
            findings.append(_make_finding(
                cis_id="CIS-5.2",
                severity=ScanSeverity.CRITICAL,
                description=(
                    f"Hardcoded secret '{m.group(1)}' in Dockerfile ENV instruction — "
                    "inject secrets at runtime via BuildKit --secret or orchestrator env (CIS-5.2)"
                ),
                rule_slug="hardcoded_secret_in_dockerfile",
                file=rel_path,
                line=str(i),
                match=f"ENV {m.group(1)} ***REDACTED***",
            ))

        # CIS-4.1: Container running as root
        if re.match(r"USER\s+root\b", stripped, re.IGNORECASE):
            findings.append(_make_finding(
                cis_id="CIS-4.1",
                severity=ScanSeverity.HIGH,
                description=(
                    "AI agent container explicitly set to run as root — "
                    "use a non-root USER to enforce least-privilege (CIS-4.1)"
                ),
                rule_slug="agent_running_as_root",
                file=rel_path,
                line=str(i),
                match=stripped,
            ))

        if re.match(r"FROM\s+", stripped, re.IGNORECASE):
            has_from = True
        if re.match(r"USER\s+(?!root\b)", stripped, re.IGNORECASE):
            has_nonroot_user = True

    # CIS-5.4: No non-root USER directive at all
    if has_from and not has_nonroot_user:
        findings.append(_make_finding(
            cis_id="CIS-5.4",
            severity=ScanSeverity.MEDIUM,
            description=(
                "Dockerfile has no non-root USER instruction — "
                "agent container defaults to root; add a non-root USER for identity isolation (CIS-5.4)"
            ),
            rule_slug="no_nonroot_user_in_dockerfile",
            file=rel_path,
            line=None,
            match=None,
        ))
    return findings

# Code-block helper: the flagged line with 2 lines of context either side
def _build_code_block(content: str, line: Optional[str]) -> Optional[str]:
    try:
        line_number = int(line) if line else 0
    except (TypeError, ValueError):
        return None
    if line_number <= 0:
        return None
    lines = content.splitlines()
    start = max(0, line_number - 3)
    end = min(len(lines), line_number + 2)
    return "\n".join(lines[start:end]) if start < end else None


def _attach_code_blocks(findings: List[ScanFinding], content: str) -> List[ScanFinding]:
    for f in findings:
        if not f.code_block:
            f.code_block = _build_code_block(content, f.line)
    return findings

# Finding factory helper
def _make_finding(
    *,
    cis_id: str,
    severity: ScanSeverity,
    description: str,
    rule_slug: str,
    file: str,
    line: Optional[str],
    match: Optional[str],
) -> ScanFinding:
    safeguard = _CIS_SAFEGUARDS.get(cis_id, {})
    control_num = safeguard.get("control", "?")
    control_title = safeguard.get("title", "CIS Controls v8.1")
    return ScanFinding(
        policy=f"cis_agent:{cis_id}:{rule_slug}",
        severity=severity,
        description=description,
        code=cis_id,
        column=control_title,
        deny=[f"CIS Control {control_num}: {control_title}"],
        match=match[:500] if match else None,
        file=file,
        line=line,
    )

# Per-line scanner
def _scan_lines(
    content: str,
    rel_path: str,
    rules: List[_Rule],
) -> List[ScanFinding]:
    """Run line-by-line regex rules, de-duplicating on (cis_id, line_number)."""
    findings: List[ScanFinding] = []
    seen: Set[Tuple[str, int]] = set()
    for i, line in enumerate(content.splitlines(), 1):
        for cis_id, severity, pattern, description in rules:
            if not pattern.search(line):
                continue
            key = (cis_id, i)
            if key in seen:
                continue
            seen.add(key)
            safeguard = _CIS_SAFEGUARDS.get(cis_id, {})
            control_num = safeguard.get("control", "?")
            control_title = safeguard.get("title", "CIS Controls v8.1")
            findings.append(ScanFinding(
                policy=f"cis_agent:{cis_id}:{pattern.pattern[:50].replace(' ', '_')}",
                severity=severity,
                description=description,
                code=cis_id,
                        column=control_title,
                deny=[f"CIS Control {control_num}: {control_title}"],
                match=line.strip()[:500],
                file=rel_path,
                line=str(i),
            ))
    return findings

# File-level dispatcher
def _scan_file(path: Path, rel_path: str) -> List[ScanFinding]:
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    name = path.name.lower()
    suffix = path.suffix.lower()
    findings: List[ScanFinding] = []

    # ── Specialised file checks ──────────────────────────────────────────
    if name in ("requirements.txt",) or re.match(r"requirements[-_].*\.txt$", name):
        return _attach_code_blocks(_check_requirements_txt(content, rel_path), content)

    if name == "package.json":
        return _attach_code_blocks(_check_package_json(content, rel_path), content)

    if name.endswith(".env.example") or name.endswith(".env.template"):
        return _attach_code_blocks(_check_env_template(content, rel_path), content)

    if name.startswith("dockerfile") or name.startswith("docker-compose"):
        return _attach_code_blocks(_check_dockerfile(content, rel_path), content)

    # ── Code & config files — line-by-line rules ─────────────────────────
    if suffix in (_CODE_EXTS | _CONFIG_EXTS):
        findings += _scan_lines(content, rel_path, _LINE_RULES)

    return _attach_code_blocks(findings, content)

# Simple fallback scoring (used when OPABasedScoreAdapter is unavailable)
_SEV_WEIGHT: Dict[ScanSeverity, int] = {
    ScanSeverity.CRITICAL: 10,
    ScanSeverity.HIGH:      7,
    ScanSeverity.MEDIUM:    4,
    ScanSeverity.LOW:       1,
    ScanSeverity.INFO:      0,
}


def _fallback_score(findings: List[ScanFinding], total_files: int) -> float:
    if not findings or total_files == 0:
        return 100.0
    total_weight = sum(_SEV_WEIGHT.get(f.severity, 1) for f in findings)
    penalty = min(100.0, total_weight / max(total_files, 1) * 5)
    return max(0.0, round(100.0 - penalty, 2))


# Scanner class
class CisAgentScanner(BaseScanner):
    """
    CIS Controls v8.1 AI Agents Companion Guide Scanner.

    Evaluates AI-agent repositories against the CIS Critical Security Controls
    v8.1 companion guidance for autonomous and semi-autonomous agent systems,
    covering:

      • CIS-1/2  — Asset & software inventory (dependency pinning)
      • CIS-3    — Data protection (PII in logs, env templates)
      • CIS-4    — Secure configuration (debug mode, root containers)
      • CIS-5    — Account management (hardcoded credentials, no non-root user)
      • CIS-6    — Access control (wildcard permissions, missing HITL gates)
      • CIS-7    — Vulnerability management (unpinned AI package versions)
      • CIS-8    — Audit logging (print() instead of logger)
      • CIS-10   — Malware defenses (prompt injection vectors)
      • CIS-12   — Network security (plaintext HTTP, disabled TLS verification)
      • CIS-13   — Network monitoring (SSRF via user-supplied URLs)
      • CIS-16   — Application security (eval/exec with LLM output, tool re-injection)
    """

    def __init__(self) -> None:
        super().__init__("cis_agent_scanner")

    def scan(self, request: ScanRequest) -> ScanResponse:
        start_time = time.time()
        logger.info(
            "[CisAgentScanner] Scan started | scan_id=%s | repo=%s",
            request.scan_id,
            request.repo_path,
        )

        try:
            # ── Step 1: Discover relevant files ─────────────────────────
            target_files = _discover_files(request.repo_path)

            if not target_files:
                logger.info(
                    "[CisAgentScanner] No scannable files found in %s — skipping",
                    request.repo_path,
                )
                return self._create_success_response(
                    request.scan_id,
                    ScanResult(
                        scanner_type=self.scanner_type,
                        status=ScanStatus.COMPLETED,
                        findings=[],
                        scanned_files=[],
                        scan_duration=time.time() - start_time,
                        metadata={
                            "framework": "CIS Controls v8.1 AI Agents Companion Guide",
                        },
                    ),
                )

            logger.info(
                "[CisAgentScanner] Discovered %d file(s) to scan", len(target_files)
            )

            # ── Step 2: Scan each file ───────────────────────────────────
            all_findings: List[ScanFinding] = []
            scanned_files: List[str] = []
            disabled_policies = (request.metadata or {}).get("disabled_policies", {})

            for file_path in target_files:
                rel_path = str(file_path.relative_to(request.repo_path))
                file_findings = _scan_file(file_path, rel_path)
                all_findings.extend(file_findings)
                scanned_files.append(rel_path)

            # ── Step 3: Apply disabled-policy filter ─────────────────────
            if disabled_policies:
                before = len(all_findings)
                all_findings = [
                    f for f in all_findings
                    if not (disabled_policies.get(f.code or "") is False)
                ]
                removed = before - len(all_findings)
                if removed:
                    logger.info(
                        "[CisAgentScanner] Suppressed %d finding(s) via disabled_policies",
                        removed,
                    )

            # ── Step 4: Score ────────────────────────────────────────────
            overall_score = _fallback_score(all_findings, len(scanned_files))
            file_scores: Dict[str, Any] = {}
            try:
                findings_dicts = [
                    {
                        "policy":      f.policy or "",
                        "severity":    (
                            f.severity.value
                            if hasattr(f.severity, "value")
                            else str(f.severity)
                        ),
                        "description": f.description,
                        "code":        f.code,
                        "file":        f.file,
                        "line":        f.line,
                    }
                    for f in all_findings
                ]
                adapter = OPABasedScoreAdapter()
                overall_score, file_scores = adapter.calculate_score(
                    findings=findings_dicts,
                    scanned_files=scanned_files,
                )
                logger.info("[CisAgentScanner] Security score: %.2f", overall_score)
            except Exception as score_err:
                logger.warning(
                    "[CisAgentScanner] Scoring failed (non-fatal): %s", score_err
                )

            duration = time.time() - start_time

            # ── Severity breakdown ───────────────────────────────────────
            sev_counts: Dict[str, int] = {}
            for f in all_findings:
                sev = (
                    f.severity.value
                    if hasattr(f.severity, "value")
                    else str(f.severity)
                )
                sev_counts[sev] = sev_counts.get(sev, 0) + 1

            # ── CIS Control breakdown ────────────────────────────────────
            ctrl_counts: Dict[str, int] = {}
            for f in all_findings:
                ctrl = f.code or "unknown"
                ctrl_counts[ctrl] = ctrl_counts.get(ctrl, 0) + 1

            if sev_counts:
                logger.info("[CisAgentScanner] Severity breakdown: %s", sev_counts)

            metadata: Dict[str, Any] = {
                "total_files":        len(scanned_files),
                "total_findings":     len(all_findings),
                "overall_score":      overall_score,
                "file_scores":        file_scores,
                "severity_breakdown": sev_counts,
                "control_breakdown":  ctrl_counts,
                "framework":          "CIS Controls v8.1 AI Agents Companion Guide",
                "controls_covered":   sorted({f.code for f in all_findings if f.code}),
            }

            logger.info(
                "[CisAgentScanner] Scan complete | scan_id=%s | files=%d "
                "| findings=%d | score=%.2f | duration=%.2fs",
                request.scan_id,
                len(scanned_files),
                len(all_findings),
                overall_score,
                duration,
            )

            return self._create_success_response(
                request.scan_id,
                ScanResult(
                    scanner_type=self.scanner_type,
                    status=ScanStatus.COMPLETED,
                    findings=all_findings,
                    scanned_files=scanned_files,
                    scan_duration=duration,
                    metadata=metadata,
                ),
            )

        except Exception as exc:
            logger.error(
                "[CisAgentScanner] Scan failed after %.2fs: %s",
                time.time() - start_time,
                exc,
                exc_info=True,
            )
            return self._create_error_response(request.scan_id, str(exc))

# Module-level entry point — matches the scan_<type>() pattern used by
# every other Zyloch microservice so the scan controller calls it uniformly.
def scan_cis_agent(request: ScanRequest) -> ScanResponse:
    return CisAgentScanner().scan(request)


# CLI for ad-hoc testing
if __name__ == "__main__":
    import argparse
    import json as _json_cli

    parser = argparse.ArgumentParser(
        description="CIS Controls v8.1 AI Agents Companion Guide Scanner"
    )
    parser.add_argument("--repo-path",  required=True, help="Path to repository root")
    parser.add_argument("--output-dir", required=True, help="Output directory for artifacts")
    parser.add_argument("--scan-id",    default="cis-agent-test", help="Unique scan identifier")
    args = parser.parse_args()

    resp = scan_cis_agent(ScanRequest(
        repo_path=args.repo_path,
        output_dir=args.output_dir,
        scan_id=args.scan_id,
    ))
    print(_json_cli.dumps(
        resp.dict() if hasattr(resp, "dict") else resp.model_dump(),
        indent=2,
        default=str,
    ))
