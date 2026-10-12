import os
import datetime
import sys
from collections import defaultdict

# Fix Unicode encoding issues on Windows
if sys.platform == "win32":
    try:
        # Set UTF-8 encoding for stdout and stderr
        if hasattr(sys.stdout, 'reconfigure'):
            sys.stdout.reconfigure(encoding='utf-8')
            sys.stderr.reconfigure(encoding='utf-8')
        else:
            # Fallback for older Python versions
            import codecs
            if not hasattr(sys.stdout, '_detached'):
                sys.stdout = codecs.getwriter("utf-8")(sys.stdout.buffer)
                sys.stderr = codecs.getwriter("utf-8")(sys.stderr.buffer)
                sys.stdout._detached = True
                sys.stderr._detached = True
    except Exception:
        # If all else fails, just continue without Unicode handling
        pass

def safe_print(text):
    """Print text safely, handling Unicode characters on Windows"""
    try:
        print(text)
    except UnicodeEncodeError:
        # Fallback: replace problematic characters
        safe_text = text.encode('ascii', 'replace').decode('ascii')
        print(safe_text)
    except Exception:
        # If even the fallback fails, try printing without encoding
        try:
            print(str(text))
        except Exception:
            pass


SEVERITY_WEIGHTS = {
    "low": 1,
    "medium": 3,
    "critical": 5,
}

def calculate_w_total(policies):
    w_total = 0
    for policy in policies.values():
        w_total += SEVERITY_WEIGHTS.get(policy.get("severity", "").lower(), 0)
    return w_total

def calculate_scores(findings, policies, scanned_files):
    w_total = calculate_w_total(policies)
    results = {}

    if not scanned_files:
        return {}, 100

    grouped_findings = defaultdict(list)
    for finding in findings:
        grouped_findings[finding['file']].append(finding)

    for file_path in scanned_files:
        file_findings = grouped_findings.get(file_path, [])
        w_violated = 0
        violation_counts = {"low": 0, "medium": 0, "critical": 0}
        violated_policies = set()

        unique_policies_in_file = {f['policy'] for f in file_findings}

        for policy_name in unique_policies_in_file:
            policy_details = policies.get(policy_name, {})
            severity = policy_details.get("severity", "").lower()
            if severity in SEVERITY_WEIGHTS:
                weight = SEVERITY_WEIGHTS[severity]
                w_violated += weight
                violation_counts[severity] += 1
                violated_policies.add(policy_name)

        score = 100 - ((w_violated / w_total) * 100) if w_total > 0 else 100
        results[file_path] = {
            "score": score,
            "w_violated": w_violated,
            "violated_policies": ", ".join(sorted(violated_policies)),
            "counts": violation_counts,
        }
    
    # Calculate overall score as an average of individual scores
    total_individual_scores = sum(result['score'] for result in results.values())
    num_files = len(scanned_files)
    overall_average_score = total_individual_scores / num_files if num_files > 0 else 100

    return results, overall_average_score


def print_severity_summary_table(policies):
    severity_counts = defaultdict(int)
    for policy in policies.values():
        severity = policy.get("severity", "unknown").lower()
        severity_counts[severity] += 1
    
    safe_print("\n" + "="*50)
    safe_print(" " * 15 + "POLICY OVERVIEW")
    safe_print("="*50)
    
    headers = ["Severity", "Count", "Score", "Weight"]
    data = []
    total_weight = 0

    for severity, weight in SEVERITY_WEIGHTS.items():
        count = severity_counts[severity]
        current_weight = count * weight
        total_weight += current_weight
        data.append([severity.capitalize(), count, weight, current_weight])
    
    data.append(["Total", len(policies), "-", total_weight])
    
    # Determine column widths
    widths = [len(h) for h in headers]
    for row in data:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(str(cell)))
    
    # Print header
    header_line = " | ".join(headers[i].ljust(widths[i]) for i in range(len(headers)))
    safe_print(header_line)
    safe_print("-|-".join('-' * w for w in widths))

    # Print rows
    for row in data:
        row_line = " | ".join(str(row[i]).ljust(widths[i]) for i in range(len(row)))
        safe_print(row_line)
    safe_print("="*50 + "\n")


def print_score_card(scan_results, overall_average_score):
    safe_print("\n" + "="*100)
    safe_print(" " * 40 + "SCORE CARD")
    safe_print("="*100)
    
    headers = ["Workflow Name", "Violated Policies", "Low", "Med", "Crit", "Wviolated", "Score (%)"]
    
    data = []
    if not scan_results:
        safe_print("No workflows scanned or no violations found to generate a score card.")
        return
        
    for file, result in scan_results.items():
        workspace = os.environ.get("GITHUB_WORKSPACE", ".")
        rel_path = os.path.relpath(file, workspace)
        rel_path = rel_path.replace(os.path.sep, "/")

        if rel_path.startswith(".github/actions/"):
            workflow_name = rel_path[len(".github/actions/"):]
        else:
            workflow_name = os.path.basename(file)
        data.append([
            workflow_name,
            result['violated_policies'] or '""',
            result['counts']['low'],
            result['counts']['medium'],
            result['counts']['critical'],
            result['w_violated'],
            f"{result['score']:.2f}"
        ])

    # Add 'Combined' row
    if scan_results:
        combined_row = ["Combined", "-", "-", "-", "-", "-", f"{overall_average_score:.2f}"]
        data.append(combined_row)

    # Determine column widths
    widths = [len(h) for h in headers]
    for row in data:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(str(cell)))

    # Print header
    header_line = " | ".join(headers[i].ljust(widths[i]) for i in range(len(headers)))
    safe_print(header_line)
    safe_print("-|-".join('-' * w for w in widths))

    # Print rows
    for row in data:
        row_line = " | ".join(str(row[i]).ljust(widths[i]) for i in range(len(row)))
        safe_print(row_line)

    safe_print("="*100 + "\n")

def write_score_report_md(scan_results, overall_average_score, output_path):
    # output_path should be a file in the output_dir, already handled by scanner.py
    # No change needed here if output_path is passed in from scanner.py

    def get_status_emoji(score):
        if score >= 100:
            return "🟢"
        elif score >= 80:
            return "🟡"
        else:
            return "🔴"

    def get_status_label(score):
        if score >= 100:
            return "Excellent"
        elif score >= 80:
            return "Needs Attention"
        else:
            return "Critical Issues"

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write("# 🏆 **GitHub Actions Security Scoring Report**\n\n")
        f.write(f"> **Report Generated at:** `{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}`\n\n")
        f.write("## 📊 **Overall Security Score:**\n\n")
        f.write(f"### {get_status_emoji(overall_average_score)} **{overall_average_score:.2f}%** — *{get_status_label(overall_average_score)}*\n\n")
        f.write("---\n\n")
        f.write("## 📝 **Workflow/Action Scores**\n\n")
        f.write("| Workflow Name | Violated Policies | Score (%) | Status |\n")
        f.write("|:-------------:|:----------------:|:---------:|:------:|\n")
        for file, result in scan_results.items():
            workspace = os.environ.get("GITHUB_WORKSPACE", ".")
            rel_path = os.path.relpath(file, workspace)
            rel_path = rel_path.replace(os.path.sep, "/")

            if rel_path.startswith(".github/actions/"):
                workflow_name = rel_path[len(".github/actions/"):]
            else:
                workflow_name = os.path.basename(file)
            violated = result['violated_policies'] or '\"\"'
            score = result['score']
            emoji = get_status_emoji(score)
            label = get_status_label(score)
            f.write(f"| `{workflow_name}` | {violated} | **{score:.2f}** | {emoji} {label} |\n")
        # Combined row
        f.write(
                "| **Combined** | - |"
                f" **{overall_average_score:.2f}** | {get_status_emoji(overall_average_score)} {get_status_label(overall_average_score)} |\n"
            )
        f.write("\n---\n\n")
        f.write("## 🗝️ **Score Status Legend**\n")
        f.write("- 🟢 **Excellent**: 100%\n")
        f.write("- 🟡 **Needs Attention**: 80-99%\n")
        f.write("- 🔴 **Critical Issues**: <80%\n\n")
        f.write(
                "> **How to remediate?** See the "
                "[policy-user-guide](https://secure-code-dev.github.io/gha-security/Policy-Guide.html)"
                "for details on each policy and how to fix violations.\n"
            )
