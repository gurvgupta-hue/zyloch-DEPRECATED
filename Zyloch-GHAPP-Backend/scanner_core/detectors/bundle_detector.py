"""Bundle-aware sibling reference detector.

Skills are commonly distributed as a directory:

    my-skill/
    ├── SKILL.md
    ├── helper.py
    └── scripts/setup.sh

Malicious bundled scripts (Snyk's "ToxicSkills" finding, the arXiv
2510.26328 demonstration against Anthropic's PowerPoint skill) live in
the sibling files, not the SKILL.md body. We:

  1. Parse the SKILL.md body for references to local files (relative
     paths, code-fence file refs, `python foo.py` style commands).
  2. Only the referenced siblings are returned — unreferenced files in
     the directory are ignored (per user spec: "if it doesnt refrence
     it then no use for it").
  3. Cap the bundle scan at MAX_BUNDLE_FILES to keep the pipeline bounded.

Refs:
  arXiv 2510.26328 · https://arxiv.org/html/2510.26328v1
  Snyk ToxicSkills · https://snyk.io/blog/toxicskills-malicious-ai-agent-skills-clawhub/
  Repello — Skill auditing · https://repello.ai/blog/claude-code-skill-security
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import List, Set, Tuple

# Filenames containing any of these tokens are NEVER bundle-scanned —
# we treat them as data, not code/config to inspect.
SCAN_BLOCKLIST_SUFFIXES = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg",
    ".mp3", ".mp4", ".wav", ".pdf", ".zip", ".tar", ".gz",
    ".woff", ".woff2", ".ttf",
}

# We only auto-scan siblings whose extension is text-like or executable.
SCAN_ALLOWLIST_SUFFIXES = {
    ".md", ".html", ".htm", ".py", ".sh", ".bash", ".zsh",
    ".js", ".ts", ".mjs", ".cjs",
    ".rb", ".go", ".rs",
    ".json", ".yaml", ".yml", ".toml",
    ".bat", ".ps1",
    ".txt", ".env", ".ini", ".cfg",
}

MAX_BUNDLE_FILES = 50  # plugins can ship many files; raised from 20

SKILL_FILENAMES = {
    "SKILL.md", "skill.md",
    "SKILL.html", "skill.html",
    "SKILL.htm", "skill.htm",
}

# Plugin manifest entry-point filenames (Claude Code plugin convention).
PLUGIN_MANIFEST_NAMES = {"plugin.json"}

# Subdirectory conventions inside a plugin root. Each entry: (subdir, suffixes-to-scan).
PLUGIN_CONVENTIONS: List[Tuple[str, set[str]]] = [
    ("commands", {".md"}),
    ("agents", {".md"}),
    ("skills", {".md", ".html", ".htm"}),
    ("hooks", {".json", ".sh", ".bash", ".py", ".js"}),
    ("mcp", {".json"}),
]

# Reference patterns. Each capture group 1 is the referenced filename.
_REF_PATTERNS = [
    # ── shared (markdown + HTML body) ──
    # `python ./foo.py` / `bash scripts/setup.sh` / `node bin/run.js`
    re.compile(
        r"\b(?:python3?|bash|sh|zsh|node|deno|bun|ruby|rb|go run|cargo run|perl|powershell|pwsh)\s+"
        r"([\.\w/\-]+\.(?:py|sh|bash|zsh|js|mjs|cjs|ts|rb|go|rs|pl|ps1|bat))\b",
        re.IGNORECASE,
    ),
    # `subprocess.run(["python", "foo.py", …])` / `Popen(["…"])`
    re.compile(
        r"""['"]([\.\w/\-]+\.(?:py|sh|bash|zsh|js|mjs|cjs|ts|rb|go|rs|pl|ps1|bat))['"]""",
    ),
    # `./foo.py`, `./scripts/run.sh`
    re.compile(r"(?<![\w./])\./([\w/\-.]+\.\w{1,5})\b"),
    # ── markdown-flavored ──
    # Markdown code-fence info string `python:foo.py` or `python title="foo.py"`
    re.compile(r"```\w+[^\n]*?[\"' /]([\w./\-]+\.\w{1,5})[\"'\s]"),
    # Bare relative path inside backticks: `helper.py`, `scripts/setup.sh`
    re.compile(r"`([\w][\w/\-.]*\.(?:py|sh|bash|zsh|js|mjs|cjs|ts|rb|go|rs|pl|ps1|bat|json|yaml|yml|toml|env))`"),
    # Markdown link or image with relative path: [text](./foo.py)
    re.compile(r"\]\(\s*\.?/?([\w/\-.]+\.\w{1,5})\s*\)"),
    # ── HTML-flavored ──
    # <script src="./helper.py"> / <script src="helper.js">
    re.compile(
        r"""<script\b[^>]*\bsrc\s*=\s*["'](?:\.?/)?([\w/\-.]+\.\w{1,5})["']""",
        re.IGNORECASE,
    ),
    # <link href="./styles.css"> / <link href="rules.md">
    re.compile(
        r"""<link\b[^>]*\bhref\s*=\s*["'](?:\.?/)?([\w/\-.]+\.\w{1,5})["']""",
        re.IGNORECASE,
    ),
    # <iframe src="./payload.html"> / <embed src=""> / <object data="">
    re.compile(
        r"""<(?:iframe|embed|object)\b[^>]*\b(?:src|data)\s*=\s*["'](?:\.?/)?([\w/\-.]+\.\w{1,5})["']""",
        re.IGNORECASE,
    ),
    # <a href="./other.html"> — only relative paths (absolute http(s) URLs are out of bundle scope)
    re.compile(
        r"""<a\b[^>]*\bhref\s*=\s*["'](?!https?://|//|mailto:|javascript:|#)(?:\.?/)?([\w/\-.]+\.\w{1,5})["']""",
        re.IGNORECASE,
    ),
]


@dataclass(frozen=True)
class BundleRef:
    path: Path
    relation: str  # the original textual reference (truncated)


def is_skill_file(filename: str) -> bool:
    """True if filename is a recognized SKILL.{md,html,htm} (case-insensitive)."""
    return Path(filename).name in SKILL_FILENAMES


# Back-compat alias for any caller still using the .md-only name.
is_skill_md = is_skill_file


def is_plugin_manifest(filename: str) -> bool:
    """True if filename is a Claude Code plugin manifest (plugin.json).

    Matches both `<plugin>/plugin.json` and `<plugin>/.claude-plugin/plugin.json`.
    """
    name = filename.replace("\\", "/")
    if Path(name).name in PLUGIN_MANIFEST_NAMES:
        return True
    return ".claude-plugin/plugin.json" in name


def is_bundle_parent(filename: str) -> bool:
    """True for any file that acts as a bundle parent (SKILL or plugin manifest)."""
    return is_skill_file(filename) or is_plugin_manifest(filename)


def find_plugin_root(manifest_path: Path) -> Path:
    """Given a plugin.json path, return the plugin's root directory.

    For `.claude-plugin/plugin.json` the root is the parent of `.claude-plugin/`.
    For plain `plugin.json` the root is the parent of the manifest.
    """
    parent = manifest_path.parent
    if parent.name == ".claude-plugin":
        return parent.parent
    return parent


def find_plugin_contents(manifest_path: Path) -> List[BundleRef]:
    """Walk a plugin directory by Claude Code conventions and return scannable files.

    Convention subdirs scanned: commands/, agents/, skills/, hooks/, mcp/.
    Also picks up a top-level `.mcp.json` or `mcp.json`.
    Path-escape attempts are rejected. Capped at MAX_BUNDLE_FILES.
    """
    if not manifest_path.exists():
        return []
    root = find_plugin_root(manifest_path).resolve()
    seen: Set[Path] = set()
    refs: List[BundleRef] = []

    def _add(path: Path, relation: str) -> None:
        try:
            path.resolve().relative_to(root)
        except ValueError:
            return
        if path in seen or path == manifest_path.resolve():
            return
        seen.add(path)
        refs.append(BundleRef(path=path, relation=relation))

    # Convention subdirectories.
    for subdir, allowed_suffixes in PLUGIN_CONVENTIONS:
        candidate_dir = root / subdir
        if not candidate_dir.is_dir():
            continue
        for f in candidate_dir.rglob("*"):
            if len(refs) >= MAX_BUNDLE_FILES:
                return refs
            if not f.is_file():
                continue
            if f.suffix.lower() not in allowed_suffixes:
                continue
            try:
                rel = f.relative_to(root).as_posix()
            except ValueError:
                continue
            _add(f, f"{subdir}/{rel.split('/', 1)[-1]}")

    # Top-level mcp.json / .mcp.json
    for candidate_name in ("mcp.json", ".mcp.json"):
        f = root / candidate_name
        if f.is_file():
            _add(f, candidate_name)

    return refs


def find_referenced_siblings(skill_md_path: Path, text: str) -> List[BundleRef]:
    """Parse SKILL.md text and return sibling files it references.

    Only files that actually exist in the same directory tree (rooted at
    skill_md_path's parent) are returned. References escaping the parent
    via `..` are rejected.
    """
    if not skill_md_path.exists():
        return []
    parent = skill_md_path.parent.resolve()
    seen: Set[Path] = set()
    refs: List[BundleRef] = []

    for pat in _REF_PATTERNS:
        for m in pat.finditer(text):
            raw = m.group(1).strip()
            if not raw or raw in {".", "/"}:
                continue
            candidate = (parent / raw).resolve()
            try:
                # reject paths escaping the bundle root
                candidate.relative_to(parent)
            except ValueError:
                continue
            if not candidate.exists() or not candidate.is_file():
                continue
            if candidate == skill_md_path.resolve():
                continue
            suffix = candidate.suffix.lower()
            if suffix in SCAN_BLOCKLIST_SUFFIXES:
                continue
            if suffix and suffix not in SCAN_ALLOWLIST_SUFFIXES:
                # Unknown extension: skip silently to avoid noise
                continue
            if candidate in seen:
                continue
            seen.add(candidate)
            ref_text = m.group(0).strip()
            if len(ref_text) > 60:
                ref_text = ref_text[:57] + "…"
            refs.append(BundleRef(path=candidate, relation=ref_text))
            if len(refs) >= MAX_BUNDLE_FILES:
                return refs
    return refs
