"""Tests for scanner_core.policy_filter.

Covers:
- _is_disabled: direct match, slash-suffix match, absent key, None/empty inputs
- filter_findings_by_policy: removes disabled findings, keeps enabled ones,
  handles both "policies" and "detectors" keys, handles missing scanner key,
  handles empty policy_config.
- apply_policy_filter_to_results: filters across multiple scanners, rebuilds
  all_findings, recounts severity breakdown.
"""

import pytest
from scanner_core.policy_filter import (
    _is_disabled,
    filter_findings_by_policy,
    apply_policy_filter_to_results,
)


# ─── _is_disabled ─────────────────────────────────────────────────────────────

class TestIsDisabled:
    def test_direct_match_returns_true(self):
        assert _is_disabled("AWS-SEC-001", {"AWS-SEC-001": False}) is True

    def test_direct_match_enabled_returns_false(self):
        assert _is_disabled("AWS-SEC-001", {"AWS-SEC-001": True}) is False

    def test_absent_key_returns_false(self):
        assert _is_disabled("AWS-SEC-001", {"AZ-SEC-001": False}) is False

    def test_slash_suffix_match_returns_true(self):
        # "ai_keys/openai_api_key" → should match bare label "openai_api_key"
        assert _is_disabled("ai_keys/openai_api_key", {"openai_api_key": False}) is True

    def test_slash_suffix_label_enabled_returns_false(self):
        assert _is_disabled("ai_keys/openai_api_key", {"openai_api_key": True}) is False

    def test_dlp_bare_infoType_direct_match(self):
        assert _is_disabled("CREDIT_CARD_NUMBER", {"CREDIT_CARD_NUMBER": False}) is True

    def test_empty_policy_id_returns_false(self):
        assert _is_disabled("", {"AWS-SEC-001": False}) is False

    def test_empty_disabled_dict_returns_false(self):
        assert _is_disabled("AWS-SEC-001", {}) is False

    def test_none_disabled_returns_false(self):
        assert _is_disabled("AWS-SEC-001", None) is False


# ─── filter_findings_by_policy ────────────────────────────────────────────────

class TestFilterFindingsByPolicy:
    def _make_iac_finding(self, code):
        return {"code": code, "message": "test finding", "severity": "HIGH"}

    def _make_secret_finding(self, policy):
        return {"policy": policy, "message": "secret found", "severity": "CRITICAL"}

    def test_removes_disabled_iac_finding(self):
        config = {"scanners": {"terraform_aws": {"policies": {"AWS-SEC-001": False}}}}
        findings = [self._make_iac_finding("AWS-SEC-001"), self._make_iac_finding("AWS-SEC-002")]
        result = filter_findings_by_policy("terraform_aws", findings, config)
        assert len(result) == 1
        assert result[0]["code"] == "AWS-SEC-002"

    def test_keeps_enabled_iac_findings(self):
        config = {"scanners": {"terraform_aws": {"policies": {"AWS-SEC-001": True}}}}
        findings = [self._make_iac_finding("AWS-SEC-001")]
        result = filter_findings_by_policy("terraform_aws", findings, config)
        assert result == findings

    def test_removes_disabled_secret_regex_finding_via_slash_suffix(self):
        # Regex findings use "category/label" format
        config = {"scanners": {"secret_scanner": {"policies": {"openai_api_key": False}}}}
        findings = [self._make_secret_finding("ai_keys/openai_api_key")]
        result = filter_findings_by_policy("secret_scanner", findings, config)
        assert len(result) == 0

    def test_removes_disabled_dlp_finding_via_direct_match(self):
        config = {"scanners": {"secret_scanner": {"policies": {"CREDIT_CARD_NUMBER": False}}}}
        findings = [self._make_secret_finding("CREDIT_CARD_NUMBER")]
        result = filter_findings_by_policy("secret_scanner", findings, config)
        assert len(result) == 0

    def test_keeps_enabled_secret_finding(self):
        config = {"scanners": {"secret_scanner": {"policies": {"some_other_key": False}}}}
        findings = [self._make_secret_finding("ai_keys/openai_api_key")]
        result = filter_findings_by_policy("secret_scanner", findings, config)
        assert result == findings

    def test_accepts_detectors_key_as_fallback(self):
        # Some older configs may use "detectors" instead of "policies"
        config = {"scanners": {"terraform_gcp": {"detectors": {"GCP-SEC-VM-001": False}}}}
        findings = [self._make_iac_finding("GCP-SEC-VM-001")]
        result = filter_findings_by_policy("terraform_gcp", findings, config)
        assert len(result) == 0

    def test_empty_policy_config_returns_all_findings(self):
        findings = [self._make_iac_finding("AWS-SEC-001")]
        result = filter_findings_by_policy("terraform_aws", findings, {})
        assert result == findings

    def test_none_policy_config_returns_all_findings(self):
        findings = [self._make_iac_finding("AWS-SEC-001")]
        result = filter_findings_by_policy("terraform_aws", findings, None)
        assert result == findings

    def test_missing_scanner_key_returns_all_findings(self):
        config = {"scanners": {"terraform_aws": {"policies": {"AWS-SEC-001": False}}}}
        findings = [self._make_iac_finding("GCP-SEC-VM-001")]
        # terraform_gcp key not in config → no filtering
        result = filter_findings_by_policy("terraform_gcp", findings, config)
        assert result == findings

    def test_gcp_corrected_policy_ids_are_filtered(self):
        # Ensures corrected GCP codes from gcp_policy_ids.py match filter
        config = {"scanners": {"terraform_gcp": {"policies": {
            "GCP-SEC-CLOUD-001": False,
            "GCP-SEC-STORAGE-001": False,
        }}}}
        findings = [
            self._make_iac_finding("GCP-SEC-CLOUD-001"),   # should be removed
            self._make_iac_finding("GCP-SEC-STORAGE-001"), # should be removed
            self._make_iac_finding("GCP-SEC-VM-001"),      # should stay
        ]
        result = filter_findings_by_policy("terraform_gcp", findings, config)
        assert len(result) == 1
        assert result[0]["code"] == "GCP-SEC-VM-001"

    def test_empty_findings_list_returns_empty(self):
        config = {"scanners": {"terraform_aws": {"policies": {"AWS-SEC-001": False}}}}
        result = filter_findings_by_policy("terraform_aws", [], config)
        assert result == []


# ─── apply_policy_filter_to_results ───────────────────────────────────────────

class TestApplyPolicyFilterToResults:
    def _make_scan_results(self, per_scanner_findings):
        """Build a minimal combined scan_results dict.

        per_scanner_findings: { scanner_key: [finding, ...], ... }
        Each scanner value is wrapped into {"findings": [...]} as the real
        scan controller produces.
        """
        per_scanner = {
            k: {"findings": v, "findings_count": len(v)}
            for k, v in per_scanner_findings.items()
        }
        all_findings = []
        for v in per_scanner_findings.values():
            all_findings.extend(v)
        return {
            "per_scanner_results": per_scanner,
            "all_findings": all_findings,
            "scanner_results": {k: {"findings_count": len(v)} for k, v in per_scanner_findings.items()},
            "summary": {},
            "all_scanned_files": [],
        }

    def test_filters_disabled_findings_across_multiple_scanners(self):
        scan_results = self._make_scan_results({
            "terraform_aws": [
                {"code": "AWS-SEC-001", "severity": "HIGH"},
                {"code": "AWS-SEC-002", "severity": "MEDIUM"},
            ],
            "terraform_gcp": [
                {"code": "GCP-SEC-VM-001", "severity": "CRITICAL"},
            ],
        })
        policy_config = {
            "scanners": {
                "terraform_aws": {"policies": {"AWS-SEC-001": False}},
                "terraform_gcp": {"policies": {"GCP-SEC-VM-001": False}},
            }
        }

        result = apply_policy_filter_to_results(scan_results, policy_config)

        # Only AWS-SEC-002 should remain
        assert len(result["all_findings"]) == 1
        assert result["all_findings"][0]["code"] == "AWS-SEC-002"
        assert len(result["per_scanner_results"]["terraform_aws"]["findings"]) == 1
        assert len(result["per_scanner_results"]["terraform_gcp"]["findings"]) == 0

    def test_severity_breakdown_is_recounted_after_filter(self):
        scan_results = self._make_scan_results({
            "terraform_aws": [
                {"code": "AWS-SEC-001", "severity": "HIGH"},
                {"code": "AWS-SEC-002", "severity": "HIGH"},
            ]
        })
        policy_config = {
            "scanners": {"terraform_aws": {"policies": {"AWS-SEC-001": False}}}
        }

        result = apply_policy_filter_to_results(scan_results, policy_config)

        # Was 2 HIGH, now 1 HIGH (severity values are lowercased in the breakdown)
        assert result["summary"]["severity_breakdown"].get("high") == 1

    def test_empty_policy_config_returns_results_unchanged(self):
        scan_results = self._make_scan_results({
            "terraform_aws": [{"code": "AWS-SEC-001", "severity": "HIGH"}]
        })

        result = apply_policy_filter_to_results(scan_results, {})

        assert len(result["all_findings"]) == 1

    def test_secret_scanner_findings_filtered_correctly(self):
        scan_results = self._make_scan_results({
            "secret_scanner": [
                {"policy": "ai_keys/openai_api_key", "severity": "CRITICAL"},
                {"policy": "CREDIT_CARD_NUMBER", "severity": "CRITICAL"},
                {"policy": "ai_keys/github_token", "severity": "HIGH"},
            ]
        })
        policy_config = {
            "scanners": {
                "secret_scanner": {
                    "policies": {
                        "openai_api_key": False,
                        "CREDIT_CARD_NUMBER": False,
                    }
                }
            }
        }

        result = apply_policy_filter_to_results(scan_results, policy_config)

        # Only github_token finding should remain
        assert len(result["all_findings"]) == 1
        assert result["all_findings"][0]["policy"] == "ai_keys/github_token"

    def test_scanners_without_config_are_unaffected(self):
        scan_results = self._make_scan_results({
            "terraform_aws":  [{"code": "AWS-SEC-001", "severity": "HIGH"}],
            "secret_scanner": [{"policy": "ai_keys/openai_api_key", "severity": "CRITICAL"}],
        })
        # Only disable a terraform_aws policy; secret_scanner is untouched
        policy_config = {
            "scanners": {"terraform_aws": {"policies": {"AWS-SEC-001": False}}}
        }

        result = apply_policy_filter_to_results(scan_results, policy_config)

        assert len(result["per_scanner_results"]["secret_scanner"]["findings"]) == 1
        assert len(result["per_scanner_results"]["terraform_aws"]["findings"]) == 0
