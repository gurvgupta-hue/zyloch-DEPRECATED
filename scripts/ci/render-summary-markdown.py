#!/usr/bin/env python3
"""Render summary.json as Markdown for PR comments and workflow summaries."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def _format_module_tested(c: dict[str, Any]) -> str:
    pct = c.get("module_tested_pct")
    tested = c.get("files_tested")
    total = c.get("source_files_total")
    if pct is None or total is None:
        return "—"
    if total == 0:
        return "—"
    return f"{pct}% ({tested}/{total} files)"


def render_summary_markdown(
    data: dict[str, Any],
    *,
    ref: str = "",
    sha: str = "",
    run_url: str = "",
) -> str:
    rate = data["success_rate"]
    tot = data["totals"]
    badge = "✅" if rate == 100 else ("⚠️" if rate >= 80 else "❌")

    cov = data.get("coverage", {})
    overall_cov = cov.get("overall", {})

    lines = [
        f"## {badge} Module test report",
        "",
    ]
    if run_url:
        lines.append(f"Workflow run: [{sha[:12] if sha else 'details'}]({run_url}) · ref `{ref}`")
        lines.append("")

    lines += [
        "| Metric | Value |",
        "| --- | ---: |",
        f"| Success rate | **{rate}%** |",
        f"| Total tests | **{tot['tests']}** |",
        f"| Passed | **{tot['passed']}** |",
        f"| Failed | **{tot['failures']}** |",
        f"| Errors | **{tot['errors']}** |",
        f"| Duration | **{tot['time']}s** |",
    ]
    if overall_cov.get("lines_pct") is not None:
        lines += [
            f"| **Overall line coverage** | **{overall_cov['lines_pct']}%** |",
            f"| **Overall module tested** | **{_format_module_tested(overall_cov)}** |",
            f"| Statements (avg) | {overall_cov.get('statements_pct', '—')}% |",
            f"| Functions (avg) | {overall_cov.get('functions_pct', '—')}% |",
            f"| Branches (avg) | {overall_cov.get('branches_pct', '—')}% |",
        ]

    lines += [
        "",
        "### Per module",
        "",
        "| Module | Tests | Passed | Failed | Errors | Skipped | Pass rate | Line cov. | Module tested |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |",
    ]
    for m in data["modules"]:
        r = round((m["passed"] / m["tests"] * 100) if m["tests"] else 0, 1)
        c = m.get("coverage") or {}
        cov_cell = f"{c['lines_pct']}%" if c.get("lines_pct") is not None else "—"
        lines.append(
            f"| `{m['module']}` | {m['tests']} | {m['passed']} | "
            f"{m['failures']} | {m['errors']} | {m['skipped']} | {r}% | {cov_cell} | "
            f"{_format_module_tested(c)} |"
        )

    lines += [
        "",
        "**Line cov.** — % of lines executed during tests (depth within files that ran).  ",
        "**Module tested** — % of source files in the module with at least one executed line "
        f"({overall_cov.get('files_tested', '—')}/{overall_cov.get('source_files_total', '—')} files overall).",
        "",
    ]
    lines.append(
        "<sub>Updated by [Module Tests & Report](.github/workflows/run-module-tests.yml) · "
        "JUnit check annotations appear on the PR checks tab.</sub>"
    )
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--ref", default="")
    parser.add_argument("--sha", default="")
    parser.add_argument("--run-url", default="")
    args = parser.parse_args()

    data = json.loads(args.input.read_text(encoding="utf-8"))
    md = render_summary_markdown(
        data, ref=args.ref, sha=args.sha, run_url=args.run_url
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(md, encoding="utf-8")


if __name__ == "__main__":
    main()
