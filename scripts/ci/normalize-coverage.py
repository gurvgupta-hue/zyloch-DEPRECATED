#!/usr/bin/env python3
"""Normalize Jest/c8/pytest-cov coverage output into a single JSON file per module."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

# How we count "source files in this module" for module-tested % (denominator).
MODULE_SOURCE_CONFIG: dict[str, dict[str, Any]] = {
    "Zyloch-Backend": {
        "subpath": ".",
        "patterns": ["**/*.js"],
        "exclude_dir_names": {"node_modules", "test-reports", "tests"},
    },
    "Zyloch-Frontend": {
        "subpath": ".",
        "patterns": ["**/*.js", "**/*.jsx"],
        "exclude_dir_names": {
            "node_modules",
            "test-reports",
            "__tests__",
            ".next",
            "out",
            "public",
        },
    },
    "Zyloch-GHAPP-Backend": {
        "subpath": "scanner_core",
        "patterns": ["**/*.py"],
        "exclude_dir_names": {"__pycache__", "test-reports", "tests", ".pytest_cache"},
    },
}


def _pct_from_istanbul_total(total: dict[str, Any], key: str) -> float:
    block = total.get(key, {})
    if isinstance(block, dict) and "pct" in block:
        return round(float(block["pct"]), 2)
    return 0.0


def _counts_from_istanbul_total(total: dict[str, Any], key: str) -> tuple[int, int]:
    block = total.get(key, {})
    if not isinstance(block, dict):
        return 0, 0
    return int(block.get("covered", 0)), int(block.get("total", 0))


def count_files_with_coverage(data: dict[str, Any]) -> int:
    """Source files that had at least one executed line during tests (numerator)."""
    if "files" in data and isinstance(data.get("files"), dict):
        count = 0
        for info in data["files"].values():
            summary = info.get("summary", info)
            if int(summary.get("covered_lines", 0)) > 0:
                count += 1
        return count

    count = 0
    for key, info in data.items():
        if key == "total" or not isinstance(info, dict):
            continue
        lines = info.get("lines", {})
        if int(lines.get("covered", 0)) > 0:
            count += 1
    return count


def count_module_source_files(module_root: Path, module_name: str) -> int:
    """All production source files in the module (denominator)."""
    config = MODULE_SOURCE_CONFIG.get(module_name)
    if not config or not module_root.is_dir():
        return 0

    base = module_root / config["subpath"]
    if not base.is_dir():
        return 0

    exclude_names = set(config["exclude_dir_names"])
    total = 0
    for pattern in config["patterns"]:
        for path in base.glob(pattern):
            if not path.is_file():
                continue
            if any(part in exclude_names for part in path.relative_to(base).parts):
                continue
            if path.name.startswith("."):
                continue
            total += 1
    return total


def parse_istanbul_summary(data: dict[str, Any]) -> dict[str, Any]:
    total = data.get("total", {})
    lines_covered, lines_total = _counts_from_istanbul_total(total, "lines")
    return {
        "lines_pct": _pct_from_istanbul_total(total, "lines"),
        "statements_pct": _pct_from_istanbul_total(total, "statements"),
        "functions_pct": _pct_from_istanbul_total(total, "functions"),
        "branches_pct": _pct_from_istanbul_total(total, "branches"),
        "lines_covered": lines_covered,
        "lines_total": lines_total,
    }


def parse_pytest_cov(data: dict[str, Any]) -> dict[str, Any]:
    totals = data.get("totals", {})
    lines_covered = int(totals.get("covered_lines", 0))
    lines_total = int(totals.get("num_statements", 0))
    lines_pct = round(float(totals.get("percent_covered", 0)), 2)
    return {
        "lines_pct": lines_pct,
        "statements_pct": lines_pct,
        "functions_pct": round(float(totals.get("percent_covered_display", lines_pct)), 2),
        "branches_pct": round(
            (
                int(totals.get("covered_branches", 0))
                / int(totals["num_branches"])
                * 100
            )
            if int(totals.get("num_branches") or 0) > 0
            else 0.0,
            2,
        ),
        "lines_covered": lines_covered,
        "lines_total": lines_total,
    }


def find_coverage_source(search_dir: Path) -> Path | None:
    candidates = [
        search_dir / "coverage" / "coverage-summary.json",
        search_dir / "coverage-summary.json",
        search_dir / "coverage.json",
    ]
    for path in candidates:
        if path.is_file():
            return path
    for path in sorted(search_dir.rglob("coverage-summary.json")):
        return path
    for path in sorted(search_dir.rglob("coverage.json")):
        return path
    return None


def normalize(module: str, source: Path, module_root: Path | None = None) -> dict[str, Any]:
    data = json.loads(source.read_text(encoding="utf-8"))
    if "totals" in data and "percent_covered" in data.get("totals", {}):
        metrics = parse_pytest_cov(data)
    else:
        metrics = parse_istanbul_summary(data)

    files_tested = count_files_with_coverage(data)
    source_files_total = (
        count_module_source_files(module_root, module) if module_root else 0
    )
    module_tested_pct = (
        round(files_tested / source_files_total * 100, 2) if source_files_total else 0.0
    )

    return {
        "module": module,
        **metrics,
        "files_tested": files_tested,
        "source_files_total": source_files_total,
        "module_tested_pct": module_tested_pct,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--module", required=True)
    parser.add_argument("--search-dir", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument(
        "--module-root",
        type=Path,
        default=None,
        help="Module directory root for source-file counts (e.g. Zyloch-Backend)",
    )
    args = parser.parse_args()

    source = find_coverage_source(args.search_dir)
    if not source:
        print(f"No coverage file found under {args.search_dir}", file=sys.stderr)
        return 1

    payload = normalize(args.module, source, args.module_root)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(
        f"Wrote {args.output} from {source} "
        f"(lines {payload['lines_pct']}%, "
        f"module tested {payload['module_tested_pct']}% "
        f"{payload['files_tested']}/{payload['source_files_total']} files)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
