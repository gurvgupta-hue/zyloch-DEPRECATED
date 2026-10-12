
from typing import Dict, Any, List


SCANNER_KEY_MAP: Dict[str, str] = {
    "secret_scanner": "secret_scanner",
    "terraform_aws":  "terraform_aws",
    "terraform_azure": "terraform_azure",
    "terraform_gcp":  "terraform_gcp",
    "kubernetes":     "kubernetes",
    "docker":         "docker",
    "workflow":       "workflow",
    "bicep":          "bicep",
    "sbom":           "sbom",
    "spec-scanner":   "spec_scanner",
    "ai-vs-human":    "ai_vs_human",
    "ai_vs_human":    "ai_vs_human",
    "ansible":        "ansible",
    "cloudformation": "cloudformation",
    "cis-agent":      "cis_agent",
    "cis_agent":      "cis_agent",
}

# Fields checked (in order) to extract a finding's policy identifier.
_POLICY_ID_FIELDS = ("code", "cve_id", "policy", "rule_name", "rule", "type", "id")


def _get_policy_id(finding: Dict[str, Any]) -> str:
    """Return the first non-empty string policy identifier found in a finding."""
    for field in _POLICY_ID_FIELDS:
        value = finding.get(field)
        if value and isinstance(value, str):
            return value
    return ""


def _is_disabled(policy_id: str, disabled: Dict[str, Any]) -> bool:
    """
    Return True if *policy_id* is explicitly disabled (set to ``False``) in
    *disabled*.

    Handles:
    - Direct match:  ``"AWS-SEC-001"``  or  ``"CREDIT_CARD_NUMBER"``
    - Slash-suffix:  ``"ai_keys/openai_api_key"``  ->  also checks
                     ``"openai_api_key"``
    """
    if not policy_id or not disabled:
        return False

    if disabled.get(policy_id) is False:
        return True

    # For "category/label" formatted IDs check the bare label as well
    if "/" in policy_id:
        label = policy_id.rsplit("/", 1)[-1]
        if disabled.get(label) is False:
            return True

    return False


def filter_findings_by_policy(
    scanner_type: str,
    findings: List[Dict[str, Any]],
    policy_config: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """
    Remove any findings whose policy is disabled in *policy_config*.

    Args:
        scanner_type: The scanner identifier as stored in ``per_scanner_results``
                      (e.g. ``"terraform_aws"``, ``"secret_scanner"``).
        findings:     List of finding dicts to filter.
        policy_config: The ``policy_configurations`` document for the org.

    Returns:
        A new list with disabled findings removed (original list untouched).
    """
    if not policy_config or not findings:
        return findings

    scanners_cfg = policy_config.get("scanners", {})
    mapped_key = SCANNER_KEY_MAP.get(scanner_type, scanner_type)
    scanner_cfg = scanners_cfg.get(mapped_key, {})

    if not scanner_cfg:
        return findings

    # Scanner-level kill-switch: if the whole scanner is disabled, return nothing.
    if scanner_cfg.get("enabled") is False:
        return []

    # Accept both "policies" and the legacy "detectors" key for backwards compat
    disabled: Dict[str, Any] = (
        scanner_cfg.get("policies")
        or scanner_cfg.get("detectors")
        or {}
    )

    if not disabled:
        return findings

    return [f for f in findings if not _is_disabled(_get_policy_id(f), disabled)]


def apply_policy_filter_to_results(
    scan_results: Dict[str, Any],
    policy_config: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Apply the organization's policy configuration to a full combined scan result,
    suppressing disabled-policy findings across *all* scanners.

    Args:
        scan_results:  The ``combined_results`` dict returned by
                       ``ScanControllerService.scan()``.
        policy_config: The ``policy_configurations`` document for the org
                       (or ``None`` / empty dict to skip filtering).

    Returns:
        A new dict with disabled findings removed and all counts/summaries
        recalculated.  The original ``scan_results`` is not modified.
    """
    if not policy_config:
        return scan_results

    per_scanner = scan_results.get("per_scanner_results", {})
    if not per_scanner:
        return scan_results

    # 1. Filter each scanner
    updated_per_scanner: Dict[str, Any] = {}
    for scanner_type, scanner_data in per_scanner.items():
        original_findings: List[Dict[str, Any]] = scanner_data.get("findings", [])
        filtered_findings = filter_findings_by_policy(
            scanner_type=scanner_type,
            findings=original_findings,
            policy_config=policy_config,
        )
        updated_per_scanner[scanner_type] = {
            **scanner_data,
            "findings": filtered_findings,
        }

    # 2. Rebuild all_findings
    all_findings: List[Dict[str, Any]] = []
    for scanner_data in updated_per_scanner.values():
        all_findings.extend(scanner_data.get("findings", []))

    # 3. Recount severity breakdown
    severity_counts: Dict[str, int] = {}
    for finding in all_findings:
        severity = finding.get("severity", "unknown")
        if hasattr(severity, "value"):
            severity = severity.value
        elif isinstance(severity, str):
            severity = severity.lower()
        severity_counts[severity] = severity_counts.get(severity, 0) + 1

    # 4. Update per-scanner summary counts
    scanner_results = scan_results.get("scanner_results", {})
    updated_scanner_results = {
        scanner_type: {
            **summary,
            "findings_count": len(
                updated_per_scanner.get(scanner_type, {}).get("findings", [])
            ),
        }
        for scanner_type, summary in scanner_results.items()
    }

    total_findings = len(all_findings)
    total_files = len(set(scan_results.get("all_scanned_files", [])))

    return {
        **scan_results,
        "per_scanner_results": updated_per_scanner,
        "all_findings": all_findings,
        "scanner_results": updated_scanner_results,
        "summary": {
            **scan_results.get("summary", {}),
            "total_findings": total_findings,
            "total_files_scanned": total_files,
            "severity_breakdown": severity_counts,
        },
    }
