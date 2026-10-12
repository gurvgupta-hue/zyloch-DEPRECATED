from __future__ import annotations

import base64
import difflib
import hashlib
import re
from typing import Any, Dict
from urllib.parse import quote

import requests

GITHUB_API = "https://api.github.com"
REQUEST_TIMEOUT = (10, 30)


class AutofixPrError(ValueError):
    """Raised when a proposal cannot be mapped safely to a repository file."""


def _github_headers(token: str) -> Dict[str, str]:
    return {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28",
    }


def _github_request(method: str, url: str, token: str, **kwargs: Any) -> requests.Response:
    if not url.startswith(f"{GITHUB_API}/"):
        raise AutofixPrError("Refusing to send GitHub credentials to an untrusted URL")
    response = requests.request(
        method,
        url,
        headers=_github_headers(token),
        timeout=REQUEST_TIMEOUT,
        **kwargs,
    )
    response.raise_for_status()
    return response


def _repository_parts(value: str) -> tuple[str, str]:
    parts = value.strip().strip("/").split("/")
    if len(parts) != 2 or not all(re.fullmatch(r"[A-Za-z0-9_.-]+", part) for part in parts):
        raise AutofixPrError("Repository must use the owner/name format")
    return parts[0], parts[1]


def _extract_standard_fix(proposal: str) -> str:
    match = re.search(r"(?im)^(?P<heading>#{2,6})\s+[^\n]*Standard Fix[^\n]*\n", proposal)
    if not match:
        raise AutofixPrError("The proposal does not contain a Standard Fix section")

    section_level = len(match.group("heading"))
    remainder = proposal[match.end():]
    section_end = len(remainder)
    for heading in re.finditer(r"(?im)^(#{2,6})\s+[^\n]*$", remainder):
        if len(heading.group(1)) < section_level:
            section_end = heading.start()
            break
    section_body = remainder[:section_end]
    compliant = re.search(
        r"(?im)^#{3,6}\s+Fix\s*\(\s*Compliant\b[^\n]*\)[^\n]*\n(?P<body>[\s\S]*?)(?=^#{3,6}\s|^#{2}\s|\Z)",
        section_body,
    )
    if not compliant:
        raise AutofixPrError(
            "The Standard Fix section must contain a 'Fix (Compliant)' heading"
        )
    search_body = compliant.group("body")
    code = re.search(r"```[^\n]*\n(?P<code>[\s\S]*?)\n```", search_body)
    if not code or not code.group("code").strip():
        raise AutofixPrError(
            "The Standard Fix section must contain one non-empty 'Fix (Compliant)' code block"
        )
    return code.group("code").strip("\n") + "\n"


def _without_comments(value: str, path: str) -> str:
    lines = []
    extension = path.rsplit(".", 1)[-1].lower() if "." in path else ""
    for line in value.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        is_dockerfile = path.rsplit("/", 1)[-1].lower() == "dockerfile"
        if (extension in {"tf", "hcl", "yaml", "yml"} or is_dockerfile) and stripped.startswith("#"):
            continue
        if extension in {"json"} and stripped.startswith("//"):
            continue
        lines.append(stripped)
    return "\n".join(lines)


def _replace_source_context(original: str, source_context: str, replacement: str) -> str:
    source = source_context.replace("\r\n", "\n").replace("\r", "\n").strip("\n")
    if not source:
        raise AutofixPrError("Source context is required")

    occurrences = original.count(source)
    if occurrences == 1:
        start = original.index(source)
        suffix = original[start + len(source):]
        starts_at_line_boundary = start == 0 or original[start - 1] in "\r\n"
        ends_at_line_boundary = suffix.startswith(("\r\n", "\n", "\r"))
        if starts_at_line_boundary and ends_at_line_boundary:
            if replacement.endswith(("\r\n", "\n", "\r")):
                replacement = replacement.rstrip("\r\n")
            return original[:start] + replacement + suffix

    # Scanner captures can differ from GitHub's file only by line endings or
    # trailing whitespace. Match normalized lines while retaining original text.
    original_lines = original.splitlines(keepends=True)
    source_lines = source.split("\n")
    normalized_source = [line.rstrip() for line in source_lines]
    candidates = []
    for start_line in range(len(original_lines) - len(source_lines) + 1):
        candidate_lines = [
            original_lines[start_line + offset].rstrip("\r\n").rstrip()
            for offset in range(len(source_lines))
        ]
        if candidate_lines == normalized_source:
            candidates.append(start_line)

    if len(candidates) != 1:
        raise AutofixPrError(
            "The source context must match exactly one location in the repository file"
        )

    start_line = candidates[0]
    start = sum(len(line) for line in original_lines[:start_line])
    end = start + sum(len(line) for line in original_lines[start_line:start_line + len(source_lines)])
    line_endings = [
        ending
        for ending in ("\r\n", "\n", "\r")
        if original_lines[start_line].endswith(ending)
    ]
    if line_endings:
        replacement = replacement.rstrip("\r\n") + line_endings[0]
    return original[:start] + replacement + original[end:]


def _diff(original: str, updated: str, path: str) -> str:
    return "".join(
        difflib.unified_diff(
            original.splitlines(keepends=True),
            updated.splitlines(keepends=True),
            fromfile=f"a/{path}",
            tofile=f"b/{path}",
        )
    )


def create_autofix_pr(request: Dict[str, Any], token: str) -> Dict[str, Any]:
    repository = str(request.get("repository") or "").strip()
    path = str(request.get("file") or "").strip().lstrip("/")
    base_branch = str(request.get("branch") or "main").strip()
    proposal = str(request.get("proposal") or "")
    source_context = str(request.get("code_block") or "")

    if not token or not repository or not path or not proposal:
        raise AutofixPrError("token, repository, file, and proposal are required")
    if not re.fullmatch(r"[A-Za-z0-9_./-]+", path) or ".." in path.split("/"):
        raise AutofixPrError("File path is invalid")
    if not re.fullmatch(r"[A-Za-z0-9._/-]+", base_branch):
        raise AutofixPrError("Branch name is invalid")

    owner, repo_name = _repository_parts(repository)
    contents_url = (
        f"{GITHUB_API}/repos/{owner}/{repo_name}/contents/{quote(path, safe='/')}"
        f"?ref={quote(base_branch, safe='')}"
    )
    metadata = _github_request("GET", contents_url, token).json()
    if metadata.get("type") != "file" or not metadata.get("content"):
        raise AutofixPrError("The selected file cannot be edited through the GitHub Contents API")

    try:
        original = base64.b64decode(metadata["content"]).decode("utf-8")
    except (ValueError, UnicodeDecodeError) as exc:
        raise AutofixPrError("The selected file is not a UTF-8 text file") from exc

    replacement = _extract_standard_fix(proposal)
    updated = _replace_source_context(original, source_context, replacement)
    if updated == original:
        raise AutofixPrError("The proposed fix does not change the repository file")
    if _without_comments(original, path) == _without_comments(updated, path):
        raise AutofixPrError(
            "The proposed fix changes only comments; no executable or configuration change was found"
        )

    branch_key = hashlib.sha1(f"{repository}:{path}:{proposal}".encode()).hexdigest()[:10]
    branch = f"security/autofix-{branch_key}"
    base_ref = _github_request(
        "GET",
        f"{GITHUB_API}/repos/{owner}/{repo_name}/git/ref/heads/{quote(base_branch, safe='')}",
        token,
    ).json()
    base_sha = base_ref["object"]["sha"]

    try:
        _github_request(
            "POST",
            f"{GITHUB_API}/repos/{owner}/{repo_name}/git/refs",
            token,
            json={"ref": f"refs/heads/{branch}", "sha": base_sha},
        )
    except requests.HTTPError as exc:
        if exc.response is None or exc.response.status_code != 422:
            raise
        raise AutofixPrError("A PR branch for this proposal already exists") from exc

    _github_request(
        "PUT",
        f"{GITHUB_API}/repos/{owner}/{repo_name}/contents/{quote(path, safe='/')}",
        token,
        json={
            "message": "security: apply proposed IaC autofix",
            "content": base64.b64encode(updated.encode("utf-8")).decode("ascii"),
            "sha": metadata["sha"],
            "branch": branch,
        },
    )

    pr = _github_request(
        "POST",
        f"{GITHUB_API}/repos/{owner}/{repo_name}/pulls",
        token,
        json={
            "title": f"security: apply autofix for {path}"[:120],
            "head": branch,
            "base": base_branch,
            "body": (
                "## Proposed security autofix\n\n"
                f"This PR applies the reviewed autofix proposal to `{path}`.\n\n"
                "Please review the generated change and run the relevant validation before merging.\n\n"
                "```diff\n"
                f"{_diff(original, updated, path)}"
                "```"
            ),
        },
    ).json()

    return {"status": "opened", "branch": branch, "pr_url": pr.get("html_url"), "file": path}
