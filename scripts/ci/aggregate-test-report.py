#!/usr/bin/env python3
"""
Aggregate per-module JUnit XML reports into:
  - dashboard-site/index.html   — interactive HTML dashboard (Chart.js)
  - dashboard-site/summary.json — lightweight summary for Grafana / step summary
  - dashboard-site/test-history.json — rolling trend data (last 30 runs)

Usage:
  python scripts/ci/aggregate-test-report.py \
    --reports-dir  dashboard-input \
    --output       dashboard-site/index.html \
    --history      dashboard-site/test-history.json \
    --ref          main \
    --sha          abc123def456
"""

from __future__ import annotations

import argparse
import json
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


# ─────────────────────────────────────────────────────────────────────────────
# Parsing
# ─────────────────────────────────────────────────────────────────────────────

def parse_junit(path: Path) -> dict[str, Any]:
    """Parse a single JUnit XML file and return a normalised module dict."""
    root = ET.parse(path).getroot()
    suites = [root] if root.tag == "testsuite" else root.findall("testsuite")

    tests = failures = errors = skipped = 0
    duration = 0.0
    cases: list[dict[str, Any]] = []

    for suite in suites:
        tests    += int(suite.attrib.get("tests",    0))
        failures += int(suite.attrib.get("failures", 0))
        errors   += int(suite.attrib.get("errors",   0))
        skipped  += int(suite.attrib.get("skipped",  0))
        duration += float(suite.attrib.get("time",   0) or 0)

        for case in suite.findall("testcase"):
            status  = "passed"
            message = ""
            for child in case:
                if child.tag in {"failure", "error"}:
                    status  = child.tag
                    message = (child.text or child.attrib.get("message", "")).strip()
                elif child.tag == "skipped":
                    status  = "skipped"
                    message = (child.text or child.attrib.get("message", "")).strip()
            cases.append(
                {
                    "name":      case.attrib.get("name", "unknown"),
                    "classname": case.attrib.get("classname", ""),
                    "time":      float(case.attrib.get("time", 0) or 0),
                    "status":    status,
                    "message":   message[:600],
                }
            )

    passed = max(tests - failures - errors - skipped, 0)
    return {
        "module":   path.stem.replace("junit-", ""),
        "tests":    tests,
        "passed":   passed,
        "failures": failures,
        "errors":   errors,
        "skipped":  skipped,
        "time":     round(duration, 3),
        # case details are kept in-memory for HTML rendering only;
        # they are NOT written to summary.json to keep it lightweight.
        "_cases": cases,
    }


def load_coverage_files(reports_dir: Path) -> dict[str, dict[str, Any]]:
    """Load normalized coverage-<module>.json files keyed by module name."""
    result: dict[str, dict[str, Any]] = {}
    for path in sorted(reports_dir.glob("coverage-*.json")):
        if path.name in {"coverage-summary.json", "coverage.json"}:
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        module = data.get("module") or path.stem.replace("coverage-", "", 1)
        result[module] = data
    return result


def merge_coverage_into_modules(
    modules: list[dict[str, Any]],
    coverage_by_module: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    for module in modules:
        cov = coverage_by_module.get(module["module"])
        if not cov:
            continue
        module["coverage"] = {
            "lines_pct":           cov.get("lines_pct"),
            "statements_pct":      cov.get("statements_pct"),
            "functions_pct":       cov.get("functions_pct"),
            "branches_pct":        cov.get("branches_pct"),
            "lines_covered":       cov.get("lines_covered", 0),
            "lines_total":         cov.get("lines_total", 0),
            "files_tested":        cov.get("files_tested", 0),
            "source_files_total":  cov.get("source_files_total", 0),
            "module_tested_pct":   cov.get("module_tested_pct"),
        }
    return modules


def compute_overall_coverage(coverage_by_module: dict[str, dict[str, Any]]) -> dict[str, Any]:
    if not coverage_by_module:
        return {}

    total_covered = sum(int(c.get("lines_covered", 0)) for c in coverage_by_module.values())
    total_lines = sum(int(c.get("lines_total", 0)) for c in coverage_by_module.values())
    lines_pct = round((total_covered / total_lines * 100) if total_lines else 0, 2)

    def _avg(key: str) -> float:
        values = [float(c[key]) for c in coverage_by_module.values() if c.get(key) is not None]
        return round(sum(values) / len(values), 2) if values else 0.0

    files_tested = sum(int(c.get("files_tested", 0)) for c in coverage_by_module.values())
    source_files_total = sum(
        int(c.get("source_files_total", 0)) for c in coverage_by_module.values()
    )
    module_tested_pct = (
        round(files_tested / source_files_total * 100, 2) if source_files_total else 0.0
    )

    return {
        "lines_pct": lines_pct,
        "statements_pct": _avg("statements_pct"),
        "functions_pct": _avg("functions_pct"),
        "branches_pct": _avg("branches_pct"),
        "lines_covered": total_covered,
        "lines_total": total_lines,
        "files_tested": files_tested,
        "source_files_total": source_files_total,
        "module_tested_pct": module_tested_pct,
    }


# ─────────────────────────────────────────────────────────────────────────────
# History
# ─────────────────────────────────────────────────────────────────────────────

def load_history(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, list) else []
    except (json.JSONDecodeError, OSError):
        return []


def save_history(path: Path, history: list[dict[str, Any]], max_entries: int = 30) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(history[-max_entries:], indent=2), encoding="utf-8")


# ─────────────────────────────────────────────────────────────────────────────
# Summary JSON (lightweight — no case details)
# ─────────────────────────────────────────────────────────────────────────────

def build_summary(
    modules: list[dict[str, Any]],
    success_rate: float,
    overall_coverage: dict[str, Any],
) -> dict[str, Any]:
    totals = {
        "tests":    sum(m["tests"]    for m in modules),
        "passed":   sum(m["passed"]   for m in modules),
        "failures": sum(m["failures"] for m in modules),
        "errors":   sum(m["errors"]   for m in modules),
        "skipped":  sum(m["skipped"]  for m in modules),
        "time":     round(sum(m["time"] for m in modules), 3),
    }
    slim_modules = [
        {k: v for k, v in m.items() if not k.startswith("_")}
        for m in modules
    ]
    summary: dict[str, Any] = {
        "success_rate": success_rate,
        "totals":       totals,
        "modules":      slim_modules,
    }
    if overall_coverage:
        summary["coverage"] = {"overall": overall_coverage}
    return summary


# ─────────────────────────────────────────────────────────────────────────────
# HTML dashboard
# ─────────────────────────────────────────────────────────────────────────────

def _coverage_badge_class(pct: float | None) -> str:
    if pct is None:
        return "muted"
    if pct >= 80:
        return "ok"
    if pct >= 50:
        return "status-warn"
    return "fail"


def render_dashboard(
    modules: list[dict[str, Any]],
    history: list[dict[str, Any]],
    meta: dict[str, Any],
    output: Path,
    overall_coverage: dict[str, Any],
) -> None:
    totals = {
        "tests":    sum(m["tests"]    for m in modules),
        "passed":   sum(m["passed"]   for m in modules),
        "failures": sum(m["failures"] for m in modules),
        "errors":   sum(m["errors"]   for m in modules),
        "skipped":  sum(m["skipped"]  for m in modules),
        "time":     round(sum(m["time"] for m in modules), 3),
    }
    totals["success_rate"] = round(
        (totals["passed"] / totals["tests"] * 100) if totals["tests"] else 0, 2
    )

    # Chart data
    module_labels  = json.dumps([m["module"] for m in modules])
    module_passed  = json.dumps([m["passed"]  for m in modules])
    module_failed  = json.dumps([m["failures"] + m["errors"] for m in modules])
    module_skipped = json.dumps([m["skipped"] for m in modules])
    trend_labels   = json.dumps([h["timestamp"][:10] for h in history[-20:]])
    trend_rates    = json.dumps([h["success_rate"]   for h in history[-20:]])
    trend_cov      = json.dumps([h.get("coverage_lines_pct", 0) for h in history[-20:]])

    cov_labels = json.dumps([m["module"] for m in modules if m.get("coverage")])
    cov_lines  = json.dumps([m["coverage"]["lines_pct"] for m in modules if m.get("coverage")])

    # Module summary rows
    rows = []
    for m in modules:
        rate  = round((m["passed"] / m["tests"] * 100) if m["tests"] else 0, 1)
        badge = "ok" if m["failures"] + m["errors"] == 0 else "fail"
        cov   = m.get("coverage") or {}
        line_cov = cov.get("lines_pct")
        cov_cell = (
            f"<span class='{_coverage_badge_class(line_cov)}'><strong>{line_cov}%</strong></span>"
            if line_cov is not None
            else "<span class='muted'>—</span>"
        )
        mod_pct = cov.get("module_tested_pct")
        mod_files = cov.get("source_files_total")
        mod_tested = (
            f"<span class='{_coverage_badge_class(mod_pct)}'><strong>{mod_pct}%</strong></span> "
            f"<span class='muted'>({cov.get('files_tested', 0)}/{mod_files} files)</span>"
            if mod_pct is not None and mod_files
            else "<span class='muted'>—</span>"
        )
        rows.append(
            f"<tr>"
            f"<td><span class='badge {badge}'>{m['module']}</span></td>"
            f"<td>{m['tests']}</td>"
            f"<td class='ok'>{m['passed']}</td>"
            f"<td class='fail'>{m['failures']}</td>"
            f"<td class='fail'>{m['errors']}</td>"
            f"<td class='muted'>{m['skipped']}</td>"
            f"<td class='muted'>{m['time']}s</td>"
            f"<td><strong>{rate}%</strong></td>"
            f"<td>{cov_cell}</td>"
            f"<td>{mod_tested}</td>"
            f"</tr>"
        )

    cov_rows = []
    for m in modules:
        cov = m.get("coverage")
        if not cov:
            continue
        mod_pct = cov.get("module_tested_pct", "—")
        cov_rows.append(
            f"<tr>"
            f"<td><span class='badge ok'>{m['module']}</span></td>"
            f"<td class='{_coverage_badge_class(cov.get('lines_pct'))}'><strong>{cov.get('lines_pct', '—')}%</strong></td>"
            f"<td class='{_coverage_badge_class(mod_pct)}'><strong>{mod_pct}%</strong></td>"
            f"<td class='muted'>{cov.get('files_tested', 0)}/{cov.get('source_files_total', 0)}</td>"
            f"<td>{cov.get('statements_pct', '—')}%</td>"
            f"<td>{cov.get('functions_pct', '—')}%</td>"
            f"<td>{cov.get('branches_pct', '—')}%</td>"
            f"<td class='muted'>{cov.get('lines_covered', 0)}/{cov.get('lines_total', 0)} lines</td>"
            f"</tr>"
        )
    cov_table_body = "".join(cov_rows) if cov_rows else "<tr><td colspan='6' class='muted'>No coverage data for this run.</td></tr>"

    overall_lines = overall_coverage.get("lines_pct")
    cov_overall_class = _coverage_badge_class(overall_lines)
    cov_cards = ""
    if overall_coverage:
        cov_cards = f"""
    <h2 class="section-title">Code coverage</h2>
    <div class="cards cov-cards">
      <div class="card"><div class="label">Overall line coverage</div><div class="value {cov_overall_class}">{overall_lines}%</div></div>
      <div class="card"><motion.div class="label">Statements (avg)</div><div class="value muted">{overall_coverage.get('statements_pct', '—')}%</div></div>
      <div class="card"><div class="label">Functions (avg)</div><div class="value muted">{overall_coverage.get('functions_pct', '—')}%</div></div>
      <div class="card"><div class="label">Branches (avg)</div><div class="value muted">{overall_coverage.get('branches_pct', '—')}%</div></div>
      <div class="card"><div class="label">Lines covered</div><div class="value muted">{overall_coverage.get('lines_covered', 0)}/{overall_coverage.get('lines_total', 0)}</div></motion.div>
    </div>"""
        while "motion.div" in cov_cards:
            cov_cards = cov_cards.replace("motion.div", "div")

    # Failure detail blocks
    case_blocks = []
    for m in modules:
        failed_cases = [c for c in m.get("_cases", []) if c["status"] in {"failure", "error"}]
        if not failed_cases:
            continue
        items = "".join(
            f"<li>"
            f"<span class='badge fail'>{c['status']}</span> "
            f"<strong>{c['classname']}.{c['name']}</strong>"
            f"{'<pre>' + c['message'] + '</pre>' if c['message'] else ''}"
            f"</li>"
            for c in failed_cases
        )
        case_blocks.append(
            f"<section class='panel'>"
            f"<h3>❌ {m['module']} failures</h3>"
            f"<ul class='fail-list'>{items}</ul>"
            f"</section>"
        )

    overall_badge = (
        "status-ok" if totals["success_rate"] == 100
        else ("status-warn" if totals["success_rate"] >= 80 else "status-fail")
    )
    overall_icon = "✅" if totals["success_rate"] == 100 else ("⚠️" if totals["success_rate"] >= 80 else "❌")

    no_modules_msg = (
        '<p class="muted">No test reports found for this run.</p>'
        if not modules else ""
    )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Zyloch · Test Dashboard</title>
  <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
  <style>
    :root {{
      --bg:     #0b1020;
      --panel:  #121a2f;
      --border: rgba(255,255,255,0.08);
      --text:   #e8eefc;
      --muted:  #7a92c4;
      --ok:     #3dd68c;
      --warn:   #ffd166;
      --fail:   #ff6b6b;
      --accent: #6ea8fe;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ background: var(--bg); color: var(--text); font-family: Inter, ui-sans-serif, system-ui, sans-serif; }}
    a {{ color: var(--accent); }}

    .wrap {{ max-width: 1200px; margin: 0 auto; padding: 36px 20px 80px; }}

    header {{ display: flex; align-items: center; gap: 16px; margin-bottom: 8px; }}
    h1 {{ font-size: 1.6rem; font-weight: 700; }}
    .status-ok   {{ color: var(--ok);   }}
    .status-warn {{ color: var(--warn); }}
    .status-fail {{ color: var(--fail); }}

    .meta {{ color: var(--muted); font-size: 0.85rem; margin-bottom: 32px; }}
    code {{ background: rgba(255,255,255,0.07); padding: 2px 6px; border-radius: 4px; font-size: 0.8em; }}

    .cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(148px, 1fr)); gap: 14px; margin-bottom: 28px; }}
    .card {{
      background: var(--panel); border: 1px solid var(--border); border-radius: 14px;
      padding: 18px 16px;
    }}
    .card .label {{ color: var(--muted); font-size: 0.78rem; text-transform: uppercase; letter-spacing: .05em; }}
    .card .value {{ font-size: 2rem; font-weight: 800; margin-top: 6px; }}
    .section-title {{ font-size: 1.1rem; font-weight: 600; margin: 28px 0 14px; color: var(--text); }}
    .cov-cards {{ margin-bottom: 28px; }}

    .grid {{ display: grid; grid-template-columns: 1.3fr 1fr; gap: 18px; margin-bottom: 28px; }}
    .panel {{
      background: var(--panel); border: 1px solid var(--border); border-radius: 14px;
      padding: 20px;
    }}
    .panel h2, .panel h3 {{ font-size: 1rem; font-weight: 600; margin-bottom: 14px; }}

    table {{ width: 100%; border-collapse: collapse; font-size: 0.9rem; }}
    th {{ color: var(--muted); font-weight: 500; font-size: 0.78rem; text-transform: uppercase; letter-spacing: .04em; padding: 8px 6px; border-bottom: 1px solid var(--border); text-align: left; }}
    td {{ padding: 10px 6px; border-bottom: 1px solid var(--border); }}
    tr:last-child td {{ border-bottom: none; }}

    .badge {{ display: inline-block; padding: 3px 10px; border-radius: 999px; font-size: 0.78rem; font-weight: 600; }}
    .badge.ok   {{ background: rgba(61,214,140,.15); color: var(--ok);   }}
    .badge.fail {{ background: rgba(255,107,107,.15); color: var(--fail); }}

    .ok   {{ color: var(--ok);   }}
    .fail {{ color: var(--fail); }}
    .muted {{ color: var(--muted); }}

    .fail-list {{ list-style: none; padding: 0; }}
    .fail-list li {{ padding: 10px 0; border-bottom: 1px solid var(--border); }}
    .fail-list li:last-child {{ border-bottom: none; }}
    pre {{ white-space: pre-wrap; background: rgba(0,0,0,.3); padding: 8px 10px; border-radius: 8px; margin-top: 6px; font-size: 0.8rem; color: var(--muted); }}

    @media (max-width: 860px) {{ .grid {{ grid-template-columns: 1fr; }} }}
  </style>
</head>
<body>
  <div class="wrap">
    <header>
      <h1 class="{overall_badge}">{overall_icon} Zyloch Test Dashboard</h1>
    </header>
    <p class="meta">
      Run: <strong>{meta["timestamp"]}</strong> &nbsp;·&nbsp;
      Ref: <code>{meta["ref"]}</code> &nbsp;·&nbsp;
      SHA: <code>{meta["sha"][:12]}</code>
    </p>

    {no_modules_msg}

    <div class="cards">
      <div class="card">
        <div class="label">Total tests</div>
        <div class="value">{totals["tests"]}</div>
      </div>
      <div class="card">
        <div class="label">Passed</div>
        <div class="value ok">{totals["passed"]}</div>
      </div>
      <div class="card">
        <div class="label">Failed</div>
        <div class="value fail">{totals["failures"] + totals["errors"]}</div>
      </div>
      <div class="card">
        <div class="label">Skipped</div>
        <div class="value muted">{totals["skipped"]}</div>
      </div>
      <div class="card">
        <div class="label">Success rate</div>
        <div class="value {overall_badge}">{totals["success_rate"]}%</div>
      </div>
      <div class="card">
        <div class="label">Duration</div>
        <div class="value muted">{totals["time"]}s</div>
      </div>
    </div>

    {cov_cards}

    <div class="grid">
      <div class="panel">
        <h2>Results by module</h2>
        <canvas id="moduleChart" height="160"></canvas>
      </div>
      <div class="panel">
        <h2>Success rate trend (last 20 runs)</h2>
        <canvas id="trendChart" height="160"></canvas>
      </div>
    </div>

    <div class="grid">
      <div class="panel">
        <h2>Line coverage by module</h2>
        <canvas id="coverageChart" height="160"></canvas>
      </div>
      <div class="panel">
        <h2>Coverage trend (last 20 runs)</h2>
        <canvas id="coverageTrendChart" height="160"></canvas>
      </div>
    </div>

    <div class="panel" style="margin-bottom:28px">
      <h2>Coverage by module</h2>
      <table>
        <thead>
          <tr>
            <th>Module</th><th>Line cov.</th><th>Module tested</th><th>Files hit</th>
            <th>Statements</th><th>Functions</th><th>Branches</th><th>Lines hit</th>
          </tr>
        </thead>
        <tbody>
          {cov_table_body}
        </tbody>
      </table>
    </div>

    <div class="panel" style="margin-bottom:28px">
      <h2>Module summary</h2>
      <table>
        <thead>
          <tr>
            <th>Module</th><th>Tests</th><th>Passed</th>
            <th>Failed</th><th>Errors</th><th>Skipped</th>
            <th>Time</th><th>Pass rate</th><th>Line cov.</th><th>Module tested</th>
          </tr>
        </thead>
        <tbody>
          {''.join(rows)}
        </tbody>
      </table>
    </div>

    {''.join(case_blocks)}
  </div>

  <script>
    const moduleLabels  = {module_labels};
    const modulePassed  = {module_passed};
    const moduleFailed  = {module_failed};
    const moduleSkipped = {module_skipped};
    const trendLabels   = {trend_labels};
    const trendRates    = {trend_rates};
    const covLabels     = {cov_labels};
    const covLines      = {cov_lines};
    const trendCov      = {trend_cov};

    const gridOpts = {{
      color: 'rgba(255,255,255,0.06)',
    }};

    new Chart(document.getElementById('moduleChart'), {{
      type: 'bar',
      data: {{
        labels: moduleLabels,
        datasets: [
          {{ label: 'Passed',  data: modulePassed,  backgroundColor: '#3dd68c' }},
          {{ label: 'Failed',  data: moduleFailed,  backgroundColor: '#ff6b6b' }},
          {{ label: 'Skipped', data: moduleSkipped, backgroundColor: '#ffd166' }},
        ],
      }},
      options: {{
        responsive: true,
        plugins: {{ legend: {{ position: 'bottom', labels: {{ color: '#9fb0d9' }} }} }},
        scales: {{
          x: {{ stacked: true, grid: gridOpts, ticks: {{ color: '#9fb0d9' }} }},
          y: {{ stacked: true, beginAtZero: true, grid: gridOpts, ticks: {{ color: '#9fb0d9' }} }},
        }},
      }},
    }});

    new Chart(document.getElementById('trendChart'), {{
      type: 'line',
      data: {{
        labels: trendLabels,
        datasets: [{{
          label: 'Success rate %',
          data: trendRates,
          borderColor: '#6ea8fe',
          backgroundColor: 'rgba(110,168,254,0.12)',
          fill: true,
          tension: 0.3,
          pointRadius: 4,
          pointBackgroundColor: '#6ea8fe',
        }}],
      }},
      options: {{
        responsive: true,
        plugins: {{ legend: {{ labels: {{ color: '#9fb0d9' }} }} }},
        scales: {{
          x: {{ grid: gridOpts, ticks: {{ color: '#9fb0d9' }} }},
          y: {{ min: 0, max: 100, grid: gridOpts, ticks: {{ color: '#9fb0d9' }} }},
        }},
      }},
    }});

    if (covLabels.length && document.getElementById('coverageChart')) {{
      new Chart(document.getElementById('coverageChart'), {{
        type: 'bar',
        data: {{
          labels: covLabels,
          datasets: [{{
            label: 'Line coverage %',
            data: covLines,
            backgroundColor: '#a78bfa',
          }}],
        }},
        options: {{
          responsive: true,
          plugins: {{ legend: {{ display: false }} }},
          scales: {{
            x: {{ grid: gridOpts, ticks: {{ color: '#9fb0d9' }} }},
            y: {{ min: 0, max: 100, grid: gridOpts, ticks: {{ color: '#9fb0d9' }} }},
          }},
        }},
      }});
    }}

    if (trendLabels.length && document.getElementById('coverageTrendChart')) {{
      new Chart(document.getElementById('coverageTrendChart'), {{
        type: 'line',
        data: {{
          labels: trendLabels,
          datasets: [{{
            label: 'Overall line coverage %',
            data: trendCov,
            borderColor: '#a78bfa',
            backgroundColor: 'rgba(167,139,250,0.15)',
            fill: true,
            tension: 0.3,
            pointRadius: 4,
          }}],
        }},
        options: {{
          responsive: true,
          plugins: {{ legend: {{ labels: {{ color: '#9fb0d9' }} }} }},
          scales: {{
            x: {{ grid: gridOpts, ticks: {{ color: '#9fb0d9' }} }},
            y: {{ min: 0, max: 100, grid: gridOpts, ticks: {{ color: '#9fb0d9' }} }},
          }},
        }},
      }});
    }}
  </script>
</body>
</html>"""

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(html, encoding="utf-8")


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reports-dir", required=True, type=Path, help="Directory with junit-*.xml files")
    parser.add_argument("--output",      required=True, type=Path, help="Path for output index.html")
    parser.add_argument("--history",     required=True, type=Path, help="Path for test-history.json")
    parser.add_argument("--ref",  default="unknown", help="Git ref name (e.g. main)")
    parser.add_argument("--sha",  default="unknown", help="Git commit SHA")
    args = parser.parse_args()

    junit_files = sorted(args.reports_dir.glob("junit-*.xml"))
    if not junit_files:
        print(f"⚠️  No junit-*.xml files found in {args.reports_dir} — generating empty dashboard")

    modules = [parse_junit(p) for p in junit_files]

    coverage_by_module = load_coverage_files(args.reports_dir)
    modules = merge_coverage_into_modules(modules, coverage_by_module)
    overall_coverage = compute_overall_coverage(coverage_by_module)

    total_tests  = sum(m["tests"]  for m in modules)
    total_passed = sum(m["passed"] for m in modules)
    success_rate = round((total_passed / total_tests * 100) if total_tests else 0, 2)

    history = load_history(args.history)
    history_entry: dict[str, Any] = {
        "timestamp":    datetime.now(timezone.utc).isoformat(),
        "ref":          args.ref,
        "sha":          args.sha,
        "success_rate": success_rate,
        "modules": [
            {k: v for k, v in m.items() if not k.startswith("_")}
            for m in modules
        ],
    }
    if overall_coverage:
        history_entry["coverage_lines_pct"] = overall_coverage.get("lines_pct", 0)
    history.append(history_entry)
    save_history(args.history, history)

    render_dashboard(
        modules,
        history,
        {
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            "ref":       args.ref,
            "sha":       args.sha,
        },
        args.output,
        overall_coverage,
    )
    print(f"✅ Dashboard written to {args.output}")

    summary = build_summary(modules, success_rate, overall_coverage)
    summary_path = args.output.parent / "summary.json"
    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(f"✅ Summary written to {summary_path}")


if __name__ == "__main__":
    main()
