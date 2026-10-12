#!/usr/bin/env python3
import fnmatch
import json
import os
import sys
import urllib.error
import urllib.request

GH_API = "https://api.github.com"
OPENAI_API = "https://api.openai.com/v1/chat/completions"
COMMENT_MARKER = "<!-- albert-code-review -->"


def env(name, default=None, required=False):
    val = os.environ.get(name, default)
    if required and not val:
        sys.exit(f"::error::Missing required env var: {name}")
    return val


def http(url, method="GET", headers=None, data=None):
    body = json.dumps(data).encode() if isinstance(data, (dict, list)) else data
    req = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req) as resp:
            raw = resp.read().decode()
            ctype = resp.headers.get("Content-Type", "")
            return json.loads(raw) if "application/json" in ctype else raw
    except urllib.error.HTTPError as e:
        detail = e.read().decode(errors="replace")
        sys.exit(f"::error::HTTP {e.code} calling {url}\n{detail}")


def gh_headers(token, accept="application/vnd.github+json"):
    return {
        "Authorization": f"Bearer {token}",
        "Accept": accept,
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "albert-code-review",
    }


def get_pr_diff(repo, pr, token):
    url = f"{GH_API}/repos/{repo}/pulls/{pr}"
    return http(url, headers=gh_headers(token, "application/vnd.github.v3.diff"))


def filter_diff(diff, excludes, max_chars):
    """Drop excluded file sections, then truncate to a token-safe size."""
    if excludes:
        chunks, keep, cur_path = [], [], None
        for line in diff.splitlines(keepends=True):
            if line.startswith("diff --git "):
                if cur_path is not None:
                    chunks.append((cur_path, "".join(keep)))
                keep, cur_path = [line], line.split(" b/")[-1].strip()
            else:
                keep.append(line)
        if cur_path is not None:
            chunks.append((cur_path, "".join(keep)))
        kept = [
            text for path, text in chunks
            if not any(fnmatch.fnmatch(path, pat) for pat in excludes)
        ]
        diff = "".join(kept)

    truncated = False
    if len(diff) > max_chars:
        diff = diff[:max_chars]
        truncated = True
    return diff, truncated


def build_system_prompt(skill_text):
    override = """

======================================================================
CI / NON-INTERACTIVE MODE — OVERRIDE (takes precedence over Agent Rules)
======================================================================
You are running inside a GitHub Actions pipeline, reviewing a pull
request diff. There is NO human available to answer intake questions.

- Do NOT ask any intake questions and do NOT wait for answers.
- Infer language, framework, and purpose from the diff, the file paths,
  and the PR title/description provided. If key context is missing,
  state your assumption in one short line and proceed.
- Treat the code as production-bound unless the PR text clearly marks it
  WIP / prototype / draft.
- Review ONLY the added/modified lines, plus enough surrounding context
  to judge them correctly. Cite locations by file path + line or hunk.
- Produce the full structured Code Review Report exactly per the
  "Output Format" section, in GitHub-flavored Markdown.
- If there are no Critical or High findings, say so explicitly.
- Every finding needs: severity, location, issue, and a concrete fix.
- Be concise. Return ONLY the report as Markdown — no preamble, no
  sign-off, no "let me know if...".
"""
    return skill_text + override


def build_user_message(title, body, diff, truncated):
    note = "\n\n> NOTE: the diff was truncated for length; review what is shown." if truncated else ""
    return (
        f"Pull request title: {title or '(none)'}\n"
        f"Pull request description:\n{body or '(none)'}\n\n"
        f"Unified diff to review:{note}\n\n"
        f"```diff\n{diff}\n```"
    )


def call_openai(system, user, model, max_tokens, api_key, reasoning_effort):
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "max_completion_tokens": int(max_tokens),
    }
    if reasoning_effort:
        payload["reasoning_effort"] = reasoning_effort  # low | medium | high
    resp = http(OPENAI_API, method="POST", headers=headers, data=payload)
    choices = resp.get("choices") or []
    if not choices:
        sys.exit(f"::error::No choices from OpenAI.\n{json.dumps(resp)[:2000]}")
    text = (choices[0].get("message", {}).get("content") or "").strip()
    if not text:
        finish = choices[0].get("finish_reason")
        sys.exit(
            f"::error::Empty content from OpenAI (finish_reason={finish}). "
            f"Reasoning may have consumed the budget — raise ALBERT_MAX_TOKENS "
            f"or set OPENAI_REASONING_EFFORT=low.\n{json.dumps(resp)[:1500]}"
        )
    return text

def upsert_comment(repo, pr, token, body):
    body = f"{COMMENT_MARKER}\n{body}"
    list_url = f"{GH_API}/repos/{repo}/issues/{pr}/comments?per_page=100"
    existing = http(list_url, headers=gh_headers(token))
    prior = next((c for c in existing if COMMENT_MARKER in (c.get("body") or "")), None)
    if prior:
        http(f"{GH_API}/repos/{repo}/issues/comments/{prior['id']}",
             method="PATCH", headers=gh_headers(token), data={"body": body})
        print(f"Updated existing review comment #{prior['id']}")
    else:
        http(f"{GH_API}/repos/{repo}/issues/{pr}/comments",
             method="POST", headers=gh_headers(token), data={"body": body})
        print("Posted new review comment")


def main():
    repo = env("GITHUB_REPOSITORY", required=True)
    pr = env("PR_NUMBER", required=True)
    gh_token = env("GITHUB_TOKEN", required=True)

    provider = (env("ALBERT_PROVIDER", "openai") or "openai").lower()
    max_tokens = env("ALBERT_MAX_TOKENS", "16000")
    max_diff_chars = int(env("ALBERT_MAX_DIFF_CHARS", "120000"))
    skill_path = env("ALBERT_SKILL_PATH", ".github/albert/SKILL.md")
    excludes = [p.strip() for p in (env("ALBERT_EXCLUDE", "") or "").split(",") if p.strip()]

    with open(skill_path, encoding="utf-8") as f:
        skill_text = f.read()

    diff = get_pr_diff(repo, pr, gh_token)
    diff, truncated = filter_diff(diff, excludes, max_diff_chars)
    if not diff.strip():
        upsert_comment(repo, pr, gh_token,
                       "**Albert** found no reviewable changes in this PR "
                       "(all changed files were excluded or the diff was empty).")
        return

    system = build_system_prompt(skill_text)
    user = build_user_message(env("PR_TITLE"), env("PR_BODY"), diff, truncated)

    if provider == "openai":
        model = env("ALBERT_MODEL", "gpt-4.1-mini")
        api_key = env("OPENAI_API_KEY", required=True)
        reasoning_effort = env("OPENAI_REASONING_EFFORT")  # optional
        report = call_openai(system, user, model, max_tokens, api_key, reasoning_effort)
    else:
        sys.exit(f"::error::Unknown ALBERT_PROVIDER '{provider}' (use 'openai').")

    header = f"**Albert — Code Review** · `{provider}` / `{model}`\n\n"
    upsert_comment(repo, pr, gh_token, header + report)


if __name__ == "__main__":
    main()
