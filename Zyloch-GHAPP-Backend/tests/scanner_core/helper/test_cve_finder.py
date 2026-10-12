"""Pytests for the CVE lookup helper used by the SBOM scanner."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock, patch

import pytest

from scanner_core.helpers.cve_finder import (
    CVEMongoConnectionError,
    _doc_to_vuln,
    _epss_label,
    _extract_cvss,
    _extract_cwe,
    _extract_description,
    _extract_fix_version,
    _extract_go_imports,
    _extract_java_imports,
    _extract_js_requires,
    _extract_published,
    _extract_python_imports_from_source,
    _extract_vulnerable_signatures,
    _match_function_in_sources,
    _parse_cvss_v3_vector_score,
    _parse_cvss_v4_vector_score,
    _pkg_name_to_import_names,
    _redact_mongo_uri,
    _risk_priority,
    _version_in_range,
    analyze_reachability,
    apply_vex_statements,
    bulk_find_vulnerabilities,
    fetch_epss_scores,
    load_vex_file,
)

CVSS3_CRITICAL_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
CVSS4_CRITICAL_VECTOR = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"


class TestRedactMongoUri:
    def test_redacts_credentials(self):
        uri = "mongodb://user:pass@cluster0.example.com:27017/cvedb"
        assert _redact_mongo_uri(uri) == "mongodb://***:***@cluster0.example.com:27017/cvedb"

    def test_leaves_uri_without_credentials_untouched(self):
        uri = "mongodb://cluster0.example.com:27017/cvedb"
        assert _redact_mongo_uri(uri) == uri

    def test_leaves_non_uri_string_untouched(self):
        assert _redact_mongo_uri("not-a-uri") == "not-a-uri"


class TestParseCvssVectorScores:
    def test_parses_v3_vector(self):
        score, severity = _parse_cvss_v3_vector_score(CVSS3_CRITICAL_VECTOR)
        assert score == 9.8
        assert severity == "CRITICAL"

    def test_parses_v4_vector(self):
        score, severity = _parse_cvss_v4_vector_score(CVSS4_CRITICAL_VECTOR)
        assert score == pytest.approx(9.3)
        assert severity == "CRITICAL"

    def test_v3_parser_rejects_v4_vector(self):
        assert _parse_cvss_v3_vector_score(CVSS4_CRITICAL_VECTOR) is None

    def test_v4_parser_rejects_v3_vector(self):
        assert _parse_cvss_v4_vector_score(CVSS3_CRITICAL_VECTOR) is None

    def test_returns_none_for_empty_vector(self):
        assert _parse_cvss_v3_vector_score("") is None
        assert _parse_cvss_v4_vector_score("") is None

    def test_returns_none_for_malformed_vector(self):
        assert _parse_cvss_v3_vector_score("CVSS:3.1/garbage") is None


class TestExtractCvss:
    def test_extracts_from_nvd_v31_metric(self):
        doc = {
            "metrics": {
                "cvssMetricV31": [
                    {
                        "baseSeverity": "Critical",
                        "cvssData": {"baseScore": 9.8, "vectorString": CVSS3_CRITICAL_VECTOR},
                    }
                ]
            }
        }
        score, severity, version, vector = _extract_cvss(doc)
        assert score == 9.8
        # severity is returned verbatim from the DB doc, not upper-cased
        assert severity == "Critical"
        assert version == "3.1"
        assert vector == CVSS3_CRITICAL_VECTOR

    def test_prefers_v40_over_v31_when_both_present(self):
        doc = {
            "metrics": {
                "cvssMetricV40": [
                    {"baseSeverity": "High", "cvssData": {"baseScore": 8.1, "vectorString": CVSS4_CRITICAL_VECTOR}}
                ],
                "cvssMetricV31": [
                    {"baseSeverity": "Critical", "cvssData": {"baseScore": 9.8, "vectorString": CVSS3_CRITICAL_VECTOR}}
                ],
            }
        }
        score, severity, version, _vector = _extract_cvss(doc)
        assert version == "4.0"
        assert score == 8.1
        assert severity == "High"

    def test_prefers_source_base_severity_over_norm_cvss(self):
        # norm_cvss is the sync pipeline's normalised block; the source record's
        # own baseSeverity wins when both are present.
        doc = {
            "norm_cvss": {
                "v2": {"score": 10, "severity": "CRITICAL", "vector": "AV:N/AC:L/Au:N/C:C/I:C/A:C"},
                "primary_score": 10,
                "primary_severity": "CRITICAL",
                "primary_version": "2.0",
            },
            "metrics": {"cvssMetricV2": [{"baseSeverity": "HIGH"}]},
        }
        _score, severity, _version, _vector = _extract_cvss(doc)
        assert severity == "HIGH"

    def test_falls_back_to_norm_cvss_when_source_has_no_label(self):
        doc = {
            "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 7.5, "vectorString": CVSS3_CRITICAL_VECTOR}}]},
            "norm_cvss": {"primary_score": 7.5, "primary_severity": "HIGH", "primary_version": "3.1"},
        }
        score, severity, _version, _vector = _extract_cvss(doc)
        assert score == 7.5
        assert severity == "HIGH"

    def test_reads_nvd_cvss_v2_metric(self):
        doc = {
            "metrics": {
                "cvssMetricV2": [
                    {
                        "baseSeverity": "HIGH",
                        "cvssData": {"version": "2.0", "baseScore": 10, "vectorString": "AV:N/AC:L/Au:N/C:C/I:C/A:C"},
                    }
                ]
            }
        }
        score, severity, version, vector = _extract_cvss(doc)
        assert severity == "HIGH"
        assert score == 10.0
        assert version == "2.0"
        assert vector == "AV:N/AC:L/Au:N/C:C/I:C/A:C"

    def test_falls_back_to_norm_cvss_for_score_version_vector(self):
        doc = {
            "norm_cvss": {
                "v2": {"score": 7.5, "severity": "HIGH", "vector": "AV:N/AC:L/Au:N/C:N/I:N/A:C"},
                "primary_score": 7.5,
                "primary_severity": "HIGH",
                "primary_version": "2.0",
            },
        }
        score, severity, version, vector = _extract_cvss(doc)
        assert score == 7.5
        assert version == "2.0"
        assert vector == "AV:N/AC:L/Au:N/C:N/I:N/A:C"
        assert severity == "HIGH"

    def test_reads_osv_cvss_v2_vector(self):
        doc = {"severity": [{"type": "CVSS_V2", "score": "AV:N/AC:L/Au:N/C:C/I:C/A:C"}]}
        score, _severity, version, vector = _extract_cvss(doc)
        assert score == 10.0
        assert version == "2.0"
        assert vector == "AV:N/AC:L/Au:N/C:C/I:C/A:C"

    def test_uses_osv_database_specific_severity_verbatim_when_no_label(self):
        doc = {
            "severity": [{"type": "CVSS_V4", "score": CVSS4_CRITICAL_VECTOR}],
            "database_specific": {"severity": "MODERATE"},
        }
        score, severity, version, _vector = _extract_cvss(doc)
        # GHSA label kept exactly as stored -- not remapped to MEDIUM
        assert severity == "MODERATE"
        assert score == pytest.approx(9.3)
        assert version == "4.0"

    def test_severity_is_none_when_only_a_vector_is_present(self):
        doc = {"severity": [{"type": "CVSS_V3", "score": CVSS3_CRITICAL_VECTOR}]}
        score, severity, version, vector = _extract_cvss(doc)
        # score/version/vector still resolve from the vector...
        assert score == 9.8
        assert version == "3.1"
        assert vector == CVSS3_CRITICAL_VECTOR
        # ...but severity is never derived from it
        assert severity is None

    def test_extracts_from_mitre_cna_container(self):
        doc = {
            "containers": {
                "cna": {
                    "metrics": [
                        {
                            "cvssV3_1": {
                                "baseScore": 7.5,
                                "baseSeverity": "HIGH",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                            }
                        }
                    ]
                }
            }
        }
        score, severity, version, _vector = _extract_cvss(doc)
        assert score == 7.5
        assert severity == "HIGH"
        assert version == "3.1"

    def test_extracts_from_mitre_adp_container_when_cna_empty(self):
        doc = {
            "containers": {
                "cna": {},
                "adp": [
                    {
                        "metrics": [
                            {"cvssV3_0": {"baseScore": 5.0, "baseSeverity": "MEDIUM", "vectorString": "CVSS:3.0/x"}}
                        ]
                    }
                ],
            }
        }
        score, severity, version, _vector = _extract_cvss(doc)
        assert score == 5.0
        assert severity == "MEDIUM"
        assert version == "3.0"

    def test_returns_none_when_no_cvss_data_present(self):
        assert _extract_cvss({}) == (None, None, None, None)

    def test_severity_none_when_metrics_have_no_base_severity(self):
        doc = {"metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 7.5, "vectorString": CVSS3_CRITICAL_VECTOR}}]}}
        score, severity, _version, _vector = _extract_cvss(doc)
        assert score == 7.5
        assert severity is None


class TestExtractCwe:
    def test_uses_precomputed_norm_cwes_when_present(self):
        doc = {"norm_cwes": ["CWE-79", "CWE-79", "CWE-89"]}
        assert _extract_cwe(doc) == ["CWE-79", "CWE-89"]

    def test_extracts_from_nvd_weaknesses(self):
        doc = {
            "weaknesses": [
                {"description": [{"value": "CWE-79"}, {"value": "NVD-CWE-noinfo"}]},
            ]
        }
        assert _extract_cwe(doc) == ["CWE-79"]

    def test_extracts_from_osv_database_specific(self):
        doc = {"database_specific": {"cwe_ids": ["CWE-22", "89"]}}
        assert _extract_cwe(doc) == ["CWE-22", "CWE-89"]

    def test_extracts_from_mitre_problem_types(self):
        doc = {
            "containers": {
                "cna": {
                    "problemTypes": [
                        {"descriptions": [{"cweId": "CWE-352"}]}
                    ]
                }
            }
        }
        assert _extract_cwe(doc) == ["CWE-352"]

    def test_returns_empty_list_when_no_cwe_found(self):
        assert _extract_cwe({}) == []


class TestExtractDescription:
    def test_prefers_english_description(self):
        doc = {"descriptions": [{"lang": "fr", "value": "bonjour"}, {"lang": "en", "value": "hello"}]}
        assert _extract_description(doc) == "hello"

    def test_falls_back_to_osv_details_truncated(self):
        doc = {"details": "x" * 600}
        assert _extract_description(doc) == "x" * 500

    def test_falls_back_to_mitre_cna_descriptions(self):
        doc = {"containers": {"cna": {"descriptions": [{"lang": "en", "value": "mitre desc"}]}}}
        assert _extract_description(doc) == "mitre desc"

    def test_returns_empty_string_when_nothing_found(self):
        assert _extract_description({}) == ""


class TestExtractPublished:
    @pytest.mark.parametrize(
        "doc,expected",
        [
            ({"published": "2024-01-01"}, "2024-01-01"),
            ({"publishedDate": "2024-02-02"}, "2024-02-02"),
            ({"published_at": "2024-03-03"}, "2024-03-03"),
            ({"cveMetadata": {"datePublished": "2024-04-04"}}, "2024-04-04"),
            ({}, None),
        ],
    )
    def test_extracts_first_available_date_field(self, doc: Dict[str, Any], expected: Optional[str]):
        assert _extract_published(doc) == expected


class TestExtractFixVersion:
    def test_returns_earliest_fixed_semver(self):
        affected = [
            {"ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}]},
            {"ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.5.0"}]}]},
        ]
        assert _extract_fix_version(affected) == "1.5.0"

    def test_ignores_non_semver_ecosystem_ranges(self):
        affected = [{"ranges": [{"type": "GIT", "events": [{"fixed": "abcdef"}]}]}]
        assert _extract_fix_version(affected) is None

    def test_returns_none_when_no_fixed_events(self):
        affected = [{"ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}]}]
        assert _extract_fix_version(affected) is None

    def test_falls_back_to_raw_string_when_unparseable(self):
        affected = [{"ranges": [{"type": "SEMVER", "events": [{"fixed": "not-a-version"}]}]}]
        assert _extract_fix_version(affected) == "not-a-version"


class TestVersionInRange:
    def test_flags_conservatively_when_version_is_none(self):
        assert _version_in_range(None, []) is True

    def test_flags_conservatively_when_version_unparseable(self):
        assert _version_in_range("not-a-version", [{"ranges": []}]) is True

    def test_version_within_introduced_and_fixed_range(self):
        affected = [{"ranges": [{"type": "SEMVER", "events": [{"introduced": "1.0.0"}, {"fixed": "2.0.0"}]}]}]
        assert _version_in_range("1.5.0", affected) is True

    def test_version_at_or_after_fixed_is_not_affected(self):
        affected = [{"ranges": [{"type": "SEMVER", "events": [{"introduced": "1.0.0"}, {"fixed": "2.0.0"}]}]}]
        assert _version_in_range("2.0.0", affected) is False

    def test_version_before_introduced_is_not_affected(self):
        affected = [{"ranges": [{"type": "SEMVER", "events": [{"introduced": "1.0.0"}, {"fixed": "2.0.0"}]}]}]
        assert _version_in_range("0.9.0", affected) is False

    def test_version_after_last_affected_is_not_affected(self):
        affected = [{"ranges": [{"type": "SEMVER", "events": [{"introduced": "1.0.0"}, {"last_affected": "1.9.0"}]}]}]
        assert _version_in_range("2.0.0", affected) is False

    def test_matches_explicit_versions_list(self):
        affected = [{"versions": ["1.0.0", "1.2.0"]}]
        assert _version_in_range("1.2.0", affected) is True
        assert _version_in_range("1.3.0", affected) is False

    def test_flags_conservatively_when_no_ranges_or_versions_given(self):
        assert _version_in_range("1.0.0", [{}]) is True


class TestDocToVuln:
    @pytest.fixture(autouse=True)
    def _no_network_calls(self):
        """EPSS keeps a deliberate live-API fallback (see TestFetchEpssScores),
        but these _doc_to_vuln tests aren't testing that path - keep requests.get
        patched so nothing here can make a real HTTP call."""
        with patch("scanner_core.helpers.cve_finder.requests.get") as get_mock:
            get_mock.return_value = MagicMock(
                raise_for_status=MagicMock(return_value=None),
                json=MagicMock(return_value={"data": []}),
            )
            with patch("scanner_core.helpers.cve_finder.time.sleep"):
                yield

    def _col(self, kev_doc=None, epss_hits=None, ghsa_doc=None, ghsa_reverse_doc=None):
        """A MagicMock Mongo collection standing in for the CVE database.

        find_one is routed by query shape (kev:/id/aliases lookups); find is
        used by fetch_epss_scores's Mongo-cache pass.
        """
        col = MagicMock()

        def _find_one(query, *args, **kwargs):
            if "_id" in query and str(query["_id"]).startswith("kev:"):
                return kev_doc
            if "id" in query:
                return ghsa_doc
            if "aliases" in query:
                return ghsa_reverse_doc
            return None

        col.find_one.side_effect = _find_one
        col.find.return_value = epss_hits or []
        return col

    def test_prefers_cve_alias_but_keeps_ghsa_id(self):
        doc = {"id": "GHSA-xxxx", "aliases": ["CVE-2024-1234"], "source": "osv"}
        vuln = _doc_to_vuln(doc, self._col())
        assert vuln["cve_id"] == "CVE-2024-1234"
        assert vuln["source"] == "osv"
        assert vuln["ghsa_id"] == "GHSA-xxxx"

    def test_uses_raw_id_when_no_cve_alias_present(self):
        doc = {"id": "GHSA-xxxx", "aliases": []}
        vuln = _doc_to_vuln(doc, self._col())
        assert vuln["cve_id"] == "GHSA-xxxx"
        assert vuln["ghsa_id"] == "GHSA-xxxx"

    def test_resolves_ghsa_to_cve_via_mongo_alias_lookup(self):
        doc = {"id": "GHSA-xxxx", "aliases": []}
        col = self._col(ghsa_doc={"aliases": ["CVE-2024-7777"]})
        vuln = _doc_to_vuln(doc, col)
        assert vuln["cve_id"] == "CVE-2024-7777"
        assert vuln["ghsa_id"] == "GHSA-xxxx"

    def test_source_override_wins_over_doc_source(self):
        doc = {"id": "CVE-2024-1234", "source": "osv"}
        vuln = _doc_to_vuln(doc, self._col(), source_override="nvd")
        assert vuln["source"] == "nvd"

    def test_fields_are_fetched_from_mongo_not_defaulted(self):
        col = self._col(kev_doc={"dateAdded": "2024-01-01", "knownRansomwareCampaignUse": "Known"})
        vuln = _doc_to_vuln({"id": "CVE-2024-0001"}, col)
        assert vuln["kev"] is True
        assert vuln["kev_date_added"] == "2024-01-01"
        assert vuln["kev_ransomware"] == "Known"
        assert vuln["risk_priority"] == "IMMEDIATE"

    def test_prefers_embedded_kev_over_separate_kev_doc(self):
        # doc.kev is the sync job's in-place annotation (see the "osv:GHSA-..."
        # doc shape in Mongo: kev.in_kev/date_added/known_ransomware_campaign).
        # A stale separate kev:<CVE-ID> doc must not override it.
        doc = {
            "id": "CVE-2024-0001",
            "kev": {
                "in_kev": True,
                "date_added": "2023-05-12",
                "known_ransomware_campaign": "Unknown",
            },
        }
        col = self._col(kev_doc={"dateAdded": "1999-01-01", "knownRansomwareCampaignUse": "STALE"})
        vuln = _doc_to_vuln(doc, col)
        assert vuln["kev"] is True
        assert vuln["kev_date_added"] == "2023-05-12"
        assert vuln["kev_ransomware"] == "Unknown"

    def test_embedded_kev_false_is_trusted_without_fallback_query(self):
        doc = {"id": "CVE-2024-0001", "kev": {"in_kev": False}}
        col = self._col(kev_doc={"dateAdded": "2023-05-12"})  # would flip kev=True if consulted
        vuln = _doc_to_vuln(doc, col)
        assert vuln["kev"] is False
        col.find_one.assert_not_called()

    def test_uses_embedded_epss_from_db_verbatim(self):
        # doc.epss is the sync job's in-place annotation; score/percentile/label
        # are used exactly as stored, never recomputed.
        doc = {"id": "CVE-2024-0001", "epss": {"score": 0.22429, "percentile": 0.97419, "label": "MEDIUM"}}
        vuln = _doc_to_vuln(doc, self._col())
        assert vuln["epss_score"] == 0.22429
        assert vuln["epss_percentile"] == 0.97419
        assert vuln["epss_label"] == "MEDIUM"

    def test_embedded_epss_without_label_falls_back_to_computed_label(self):
        # Unlike CVE/CVSS severity, EPSS keeps a deliberate calculated fallback
        # (user call, 2026-09-18: "we want it EPSS live-API-fallback in code") -
        # a doc with a score but no stored label gets one computed via _epss_label().
        doc = {"id": "CVE-2024-0001", "epss": {"score": 0.95, "percentile": 0.99}}
        vuln = _doc_to_vuln(doc, self._col())
        assert vuln["epss_score"] == 0.95
        assert vuln["epss_label"] == "CRITICAL"

    def test_no_kev_or_epss_hit_leaves_fields_unset(self):
        vuln = _doc_to_vuln({"id": "CVE-2024-0001"}, self._col())
        assert vuln["kev"] is False
        assert vuln["reachability"] == "UNKNOWN"
        assert vuln["risk_priority"] == "MONITOR"
        assert vuln["vex_status"] is None

    def test_vex_not_affected_collapses_risk_priority(self):
        doc = {
            "id": "CVE-2024-0001",
            "metrics": {"cvssMetricV31": [{"baseSeverity": "Critical", "cvssData": {"baseScore": 9.8}}]},
        }
        vex_statements = {"CVE-2024-0001": [{"status": "not_affected", "justification": "", "statement_id": "s1"}]}
        vuln = _doc_to_vuln(doc, self._col(), vex_statements=vex_statements)
        assert vuln["risk_priority"] == "MONITOR"
        assert vuln["vex_status"] == "VEX:NOT_AFFECTED"

    def test_description_is_truncated_to_300_chars(self):
        doc = {"id": "CVE-2024-0001", "details": "y" * 1000}
        vuln = _doc_to_vuln(doc, self._col())
        assert len(vuln["description"]) == 300


class TestEpssLabel:
    @pytest.mark.parametrize(
        "score,expected",
        [
            (0.95, "CRITICAL"),
            (0.90, "CRITICAL"),
            (0.75, "HIGH"),
            (0.50, "HIGH"),
            (0.30, "MEDIUM"),
            (0.10, "MEDIUM"),
            (0.05, "LOW"),
            (0.01, "LOW"),
            (0.0, "MINIMAL"),
        ],
    )
    def test_maps_score_to_label(self, score: float, expected: str):
        assert _epss_label(score) == expected


class TestRiskPriority:
    def test_kev_always_wins_regardless_of_score(self):
        assert _risk_priority(cvss=1.0, epss=0.0, in_kev=True) == "IMMEDIATE"

    def test_not_reachable_collapses_to_monitor(self):
        assert _risk_priority(cvss=9.8, epss=0.9, in_kev=False, reachability="NOT_REACHABLE") == "MONITOR"

    def test_kev_overrides_not_reachable(self):
        assert _risk_priority(cvss=1.0, epss=0.0, in_kev=True, reachability="NOT_REACHABLE") == "IMMEDIATE"

    def test_reachable_with_high_cvss_is_high_not_immediate(self):
        assert _risk_priority(cvss=7.5, epss=0.0, in_kev=False, reachability="REACHABLE") == "HIGH"

    def test_reachable_with_critical_cvss_is_immediate(self):
        assert _risk_priority(cvss=9.8, epss=0.0, in_kev=False, reachability="REACHABLE") == "IMMEDIATE"

    def test_potentially_reachable_with_critical_cvss_is_immediate(self):
        assert _risk_priority(cvss=9.0, epss=0.0, in_kev=False, reachability="POTENTIALLY_REACHABLE") == "IMMEDIATE"

    def test_reachable_func_promotes_immediate_at_lower_cvss_bar(self):
        assert _risk_priority(cvss=7.0, epss=0.0, in_kev=False, reachability="REACHABLE_FUNC") == "IMMEDIATE"

    def test_reachable_func_below_cvss_bar_falls_through_to_base_matrix(self):
        assert _risk_priority(cvss=5.0, epss=0.0, in_kev=False, reachability="REACHABLE_FUNC") == "LOW"

    def test_high_epss_and_cvss_is_immediate(self):
        assert _risk_priority(cvss=7.0, epss=0.5, in_kev=False) == "IMMEDIATE"

    def test_moderate_epss_and_low_cvss_is_medium(self):
        assert _risk_priority(cvss=4.0, epss=0.02, in_kev=False) == "MEDIUM"

    def test_high_cvss_alone_is_medium(self):
        assert _risk_priority(cvss=7.5, epss=None, in_kev=False) == "MEDIUM"

    def test_low_cvss_alone_is_low(self):
        assert _risk_priority(cvss=4.5, epss=None, in_kev=False) == "LOW"

    def test_no_signals_is_monitor(self):
        assert _risk_priority(cvss=None, epss=None, in_kev=False) == "MONITOR"


class TestFetchEpssScores:
    def test_returns_empty_dict_for_empty_input(self):
        assert fetch_epss_scores(MagicMock(), []) == {}

    def test_reads_scores_from_mongo(self):
        col = MagicMock()
        col.find.return_value = [
            {"_id": "epss:CVE-2024-1234", "cve_id": "CVE-2024-1234", "score": 0.5, "percentile": 0.9, "label": "HIGH"}
        ]
        result = fetch_epss_scores(col, ["CVE-2024-1234"])
        assert result["CVE-2024-1234"] == {"score": 0.5, "percentile": 0.9, "label": "HIGH"}
        col.find.assert_called_once()

    def test_mongo_doc_without_label_falls_back_to_computed_label(self):
        # Same deliberate calculated fallback as _doc_to_vuln's embedded-EPSS
        # path - a Mongo epss: doc with a score but no stored label field.
        col = MagicMock()
        col.find.return_value = [
            {"_id": "epss:CVE-2024-1234", "cve_id": "CVE-2024-1234", "score": 0.5, "percentile": 0.9}
        ]
        result = fetch_epss_scores(col, ["CVE-2024-1234"])
        assert result["CVE-2024-1234"]["label"] == "HIGH"

    def test_cves_missing_from_mongo_fall_back_to_live_api(self):
        # EPSS keeps its live api.first.org fallback deliberately (user call:
        # DB-only is not required here, unlike CVE/CVSS lookups) - a CVE with
        # no Mongo doc must still be resolved via the API, not silently omitted.
        col = MagicMock()
        col.find.return_value = []
        api_response = MagicMock()
        api_response.raise_for_status = MagicMock(return_value=None)
        api_response.json.return_value = {
            "data": [{"cve": "CVE-2024-9999", "epss": "0.01234", "percentile": "0.5"}]
        }
        with patch(
            "scanner_core.helpers.cve_finder.requests.get", return_value=api_response
        ) as get_mock, patch("scanner_core.helpers.cve_finder.time.sleep"):
            result = fetch_epss_scores(col, ["CVE-2024-9999"])
        get_mock.assert_called_once()
        assert result["CVE-2024-9999"]["score"] == pytest.approx(0.01234)
        assert result["CVE-2024-9999"]["label"] == "LOW"

    def test_mongo_lookup_failure_falls_back_to_live_api(self):
        from pymongo.errors import PyMongoError

        col = MagicMock()
        col.find.side_effect = PyMongoError("boom")
        api_response = MagicMock()
        api_response.raise_for_status = MagicMock(return_value=None)
        api_response.json.return_value = {
            "data": [{"cve": "CVE-2024-0001", "epss": "0.02", "percentile": "0.4"}]
        }
        with patch(
            "scanner_core.helpers.cve_finder.requests.get", return_value=api_response
        ), patch("scanner_core.helpers.cve_finder.time.sleep"):
            result = fetch_epss_scores(col, ["CVE-2024-0001"])
        assert result["CVE-2024-0001"]["score"] == pytest.approx(0.02)


class TestPkgNameToImportNames:
    def test_normalizes_hyphenated_package_name(self):
        assert "python_dateutil" in _pkg_name_to_import_names("python-dateutil")

    def test_includes_known_alias(self):
        assert "yaml" in _pkg_name_to_import_names("PyYAML")

    def test_strips_python_prefix(self):
        assert "dotenv" in _pkg_name_to_import_names("python-dotenv")


class TestExtractPythonImportsFromSource:
    def test_extracts_import_and_from_import(self):
        source = "import requests\nfrom flask import Flask\n"
        assert _extract_python_imports_from_source(source) == {"requests", "flask"}

    def test_excludes_stdlib_modules(self):
        source = "import os\nimport json\nimport aiohttp\n"
        assert _extract_python_imports_from_source(source) == {"aiohttp"}

    def test_falls_back_to_regex_on_syntax_error(self):
        source = "import requests\ndef broken(:\n"
        assert "requests" in _extract_python_imports_from_source(source)


class TestExtractJsRequires:
    def test_extracts_commonjs_require(self):
        source = "const lodash = require('lodash');"
        assert "lodash" in _extract_js_requires(source)

    def test_extracts_es6_import(self):
        source = "import express from 'express';"
        assert "express" in _extract_js_requires(source)

    def test_ignores_relative_imports(self):
        source = "import foo from './foo';\nconst bar = require('../bar');"
        assert _extract_js_requires(source) == set()

    def test_scoped_package_uses_top_segment(self):
        source = "import { z } from '@scope/pkg';"
        assert "@scope" in _extract_js_requires(source)


class TestExtractJavaImports:
    def test_extracts_group_and_artifact_prefix(self):
        source = "import org.apache.commons.lang3.StringUtils;\n"
        assert "org.apache" in _extract_java_imports(source)

    def test_ignores_single_segment_imports(self):
        assert _extract_java_imports("import java;\n") == set()


class TestExtractGoImports:
    def test_extracts_dotted_module_paths(self):
        source = 'import (\n\t"github.com/gin-gonic/gin"\n\t"fmt"\n)\n'
        imports = _extract_go_imports(source)
        assert "github.com/gin-gonic/gin" in imports
        assert "fmt" not in imports


class TestExtractVulnerableSignatures:
    def test_extracts_from_osv_ecosystem_specific_affected_functions(self):
        doc = {"affected": [{"ecosystem_specific": {"affected_functions": ["joblib.Parallel"]}}]}
        sigs = _extract_vulnerable_signatures(doc)
        assert sigs[0]["func"] == "Parallel"
        assert sigs[0]["pattern"].search("Parallel(n_jobs=4)")

    def test_extracts_from_github_database_specific_affected_functions(self):
        doc = {"affected": [{"database_specific": {"affected_functions": ["load"]}}]}
        sigs = _extract_vulnerable_signatures(doc)
        assert sigs[0]["func"] == "load"

    def test_extracts_from_description_backtick_function_span(self):
        doc = {"affected": [{"details": "vulnerable via the `Parallel()` class"}]}
        sigs = _extract_vulnerable_signatures(doc)
        assert any(s["func"] == "Parallel" for s in sigs)

    def test_returns_empty_list_when_no_function_data_present(self):
        assert _extract_vulnerable_signatures({"affected": [{}]}) == []


class TestMatchFunctionInSources:
    def test_matches_bare_function_call(self):
        doc = {"affected": [{"ecosystem_specific": {"affected_functions": ["joblib.Parallel"]}}]}
        sigs = _extract_vulnerable_signatures(doc)
        assert _match_function_in_sources(sigs, [("app.py", "Parallel(n_jobs=4)")]) is True

    def test_no_match_when_function_absent_from_sources(self):
        doc = {"affected": [{"ecosystem_specific": {"affected_functions": ["joblib.Parallel"]}}]}
        sigs = _extract_vulnerable_signatures(doc)
        assert _match_function_in_sources(sigs, [("app.py", "import joblib\n")]) is False


class TestAnalyzeReachability:
    def test_pypi_package_imported_in_prod_file_is_reachable(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("import requests\n", encoding="utf-8")
        deps = [{"moduleName": "requests", "versionInfo": "2.31.0", "packageManager": "pypi"}]

        reach = analyze_reachability(deps, str(tmp_path))

        assert reach[("requests", "pypi")] == "REACHABLE"

    def test_pypi_package_only_in_tests_is_potentially_reachable(self, tmp_path: Path):
        tests_dir = tmp_path / "tests"
        tests_dir.mkdir()
        (tests_dir / "test_app.py").write_text("import faker\n", encoding="utf-8")
        deps = [{"moduleName": "faker", "versionInfo": "1.0", "packageManager": "pypi"}]

        reach = analyze_reachability(deps, str(tmp_path))

        assert reach[("faker", "pypi")] == "POTENTIALLY_REACHABLE"

    def test_pypi_package_unused_is_not_reachable(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("import os\n", encoding="utf-8")
        deps = [{"moduleName": "unused-pkg", "versionInfo": "1.0", "packageManager": "pypi"}]

        reach = analyze_reachability(deps, str(tmp_path))

        assert reach[("unused-pkg", "pypi")] == "NOT_REACHABLE"

    def test_pypi_import_via_local_module_chain_is_reachable(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("import utils\n", encoding="utf-8")
        (tmp_path / "utils.py").write_text("import aiohttp\n", encoding="utf-8")
        deps = [{"moduleName": "aiohttp", "versionInfo": "3.9", "packageManager": "pypi"}]

        reach = analyze_reachability(deps, str(tmp_path))

        # utils.py is itself walked as a prod file, so its import of aiohttp
        # lands directly in prod_imports (transitive resolution only matters
        # when the local module is otherwise excluded, e.g. a test file).
        assert reach[("aiohttp", "pypi")] == "REACHABLE"

    def test_pypi_function_level_match_upgrades_to_reachable_func(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(
            "from joblib import Parallel\nParallel(n_jobs=4)(delayed(f)(x) for x in xs)\n",
            encoding="utf-8",
        )
        deps = [{"moduleName": "joblib", "versionInfo": "1.2.0", "packageManager": "pypi"}]
        vuln_docs = {"joblib": {"affected": [{"ecosystem_specific": {"affected_functions": ["joblib.Parallel"]}}]}}

        reach = analyze_reachability(deps, str(tmp_path), vuln_docs=vuln_docs)

        assert reach[("joblib", "pypi")] == "REACHABLE_FUNC"

    def test_pypi_import_without_function_call_stays_reachable(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("import joblib\njoblib.dump(model, 'f.pkl')\n", encoding="utf-8")
        deps = [{"moduleName": "joblib", "versionInfo": "1.2.0", "packageManager": "pypi"}]
        vuln_docs = {"joblib": {"affected": [{"ecosystem_specific": {"affected_functions": ["joblib.Parallel"]}}]}}

        reach = analyze_reachability(deps, str(tmp_path), vuln_docs=vuln_docs)

        assert reach[("joblib", "pypi")] == "REACHABLE"

    def test_npm_package_required_in_prod_file_is_reachable(self, tmp_path: Path):
        (tmp_path / "index.js").write_text("const express = require('express');\n", encoding="utf-8")
        deps = [{"moduleName": "express", "versionInfo": "4.18.0", "packageManager": "npm"}]

        reach = analyze_reachability(deps, str(tmp_path))

        assert reach[("express", "npm")] == "REACHABLE"

    def test_maven_package_imported_is_reachable(self, tmp_path: Path):
        # _extract_java_imports only keeps the first two dotted segments of an
        # import statement, so the groupId here must be two segments to match.
        src = tmp_path / "src"
        src.mkdir()
        (src / "App.java").write_text("import org.junit.jupiter.api.Test;\n", encoding="utf-8")
        deps = [{"moduleName": "org.junit:jupiter", "versionInfo": "5.10.0", "packageManager": "maven"}]

        reach = analyze_reachability(deps, str(tmp_path))

        assert reach[("org.junit:jupiter", "maven")] == "REACHABLE"

    def test_infra_file_reference_promotes_unused_pypi_package(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("import os\n", encoding="utf-8")
        (tmp_path / "Dockerfile").write_text("RUN pip install gunicorn\n", encoding="utf-8")
        deps = [{"moduleName": "gunicorn", "versionInfo": "21.2.0", "packageManager": "pypi"}]

        reach = analyze_reachability(deps, str(tmp_path))

        assert reach[("gunicorn", "pypi")] == "POTENTIALLY_REACHABLE"

    def test_returns_empty_map_when_repo_path_missing(self):
        deps = [{"moduleName": "requests", "versionInfo": "2.31.0", "packageManager": "pypi"}]
        assert analyze_reachability(deps, "") == {}

    def test_returns_empty_map_when_repo_path_not_a_directory(self, tmp_path: Path):
        deps = [{"moduleName": "requests", "versionInfo": "2.31.0", "packageManager": "pypi"}]
        assert analyze_reachability(deps, str(tmp_path / "missing")) == {}


class TestLoadVexFile:
    def test_returns_empty_dict_when_path_missing(self):
        assert load_vex_file("") == {}

    def test_returns_empty_dict_when_file_does_not_exist(self, tmp_path: Path):
        assert load_vex_file(str(tmp_path / "missing.json")) == {}

    def test_parses_openvex_statements(self, tmp_path: Path):
        vex_path = tmp_path / "vex.json"
        vex_path.write_text(
            json.dumps(
                {
                    "statements": [
                        {
                            "vulnerability": {"id": "CVE-2024-1234"},
                            "status": "not_affected",
                            "justification": "component_not_present",
                            "@id": "stmt-1",
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        result = load_vex_file(str(vex_path))
        assert result["CVE-2024-1234"][0]["status"] == "not_affected"
        assert result["CVE-2024-1234"][0]["statement_id"] == "stmt-1"

    def test_resolves_cve_from_aliases_when_id_is_not_cve(self, tmp_path: Path):
        vex_path = tmp_path / "vex.json"
        vex_path.write_text(
            json.dumps(
                {
                    "statements": [
                        {
                            "vulnerability": {"id": "GHSA-xxxx", "aliases": ["CVE-2024-5678"]},
                            "status": "fixed",
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        result = load_vex_file(str(vex_path))
        assert "CVE-2024-5678" in result

    def test_skips_expired_statements(self, tmp_path: Path):
        vex_path = tmp_path / "vex.json"
        vex_path.write_text(
            json.dumps(
                {
                    "statements": [
                        {
                            "vulnerability": {"id": "CVE-2024-1234"},
                            "status": "not_affected",
                            "expiry_time": "2000-01-01T00:00:00Z",
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        assert load_vex_file(str(vex_path)) == {}

    def test_parses_cyclonedx_vex_statements(self, tmp_path: Path):
        vex_path = tmp_path / "vex.json"
        vex_path.write_text(
            json.dumps(
                {
                    "vulnerabilities": [
                        {
                            "id": "CVE-2024-9999",
                            "bom-ref": "vuln-1",
                            "analysis": {"state": "resolved", "justification": "vulnerable_code_not_present"},
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        result = load_vex_file(str(vex_path))
        assert result["CVE-2024-9999"][0]["status"] == "fixed"

    def test_returns_empty_dict_for_invalid_json(self, tmp_path: Path):
        vex_path = tmp_path / "vex.json"
        vex_path.write_text("{not-valid-json", encoding="utf-8")
        assert load_vex_file(str(vex_path)) == {}


class TestApplyVexStatements:
    def _vuln(self, **overrides) -> Dict[str, Any]:
        base = {"cve_id": "CVE-2024-1234", "kev": False, "cvss_score": 9.8, "risk_priority": "MEDIUM"}
        base.update(overrides)
        return base

    def test_noop_when_no_statements(self):
        results = {("pkg", "pypi"): [self._vuln()]}
        apply_vex_statements(results, {})
        assert results[("pkg", "pypi")][0]["risk_priority"] == "MEDIUM"

    def test_not_affected_collapses_priority_to_monitor(self):
        results = {("pkg", "pypi"): [self._vuln()]}
        vex = {"CVE-2024-1234": [{"status": "not_affected", "justification": "", "statement_id": "s1"}]}

        apply_vex_statements(results, vex)

        vuln = results[("pkg", "pypi")][0]
        assert vuln["risk_priority"] == "MONITOR"
        assert vuln["vex_status"] == "VEX:NOT_AFFECTED"

    def test_kev_overrides_not_affected_statement(self):
        results = {("pkg", "pypi"): [self._vuln(kev=True, risk_priority="IMMEDIATE")]}
        vex = {"CVE-2024-1234": [{"status": "not_affected", "justification": "", "statement_id": "s1"}]}

        apply_vex_statements(results, vex)

        assert results[("pkg", "pypi")][0]["risk_priority"] == "IMMEDIATE"

    def test_affected_promotes_monitor_to_high_when_cvss_is_high(self):
        results = {("pkg", "pypi"): [self._vuln(risk_priority="MONITOR", cvss_score=8.0)]}
        vex = {"CVE-2024-1234": [{"status": "affected", "justification": "", "statement_id": "s1"}]}

        apply_vex_statements(results, vex)

        assert results[("pkg", "pypi")][0]["risk_priority"] == "HIGH"

    def test_most_recent_statement_wins(self):
        results = {("pkg", "pypi"): [self._vuln()]}
        vex = {
            "CVE-2024-1234": [
                {"status": "affected", "justification": "", "statement_id": "s1"},
                {"status": "not_affected", "justification": "", "statement_id": "s2"},
            ]
        }

        apply_vex_statements(results, vex)

        assert results[("pkg", "pypi")][0]["vex_statement_id"] == "s2"
        assert results[("pkg", "pypi")][0]["risk_priority"] == "MONITOR"


class TestBulkFindVulnerabilities:
    def test_returns_empty_map_when_cve_db_unavailable(self):
        with patch(
            "scanner_core.helpers.cve_finder.get_cve_collection",
            side_effect=CVEMongoConnectionError("not configured"),
        ):
            result = bulk_find_vulnerabilities([{"moduleName": "requests", "versionInfo": "2.0", "packageManager": "pypi"}])

        assert result == {}

    def test_returns_empty_map_for_no_dependencies(self):
        with patch("scanner_core.helpers.cve_finder.get_cve_collection", return_value=MagicMock()):
            assert bulk_find_vulnerabilities([]) == {}

    def test_ignores_dependencies_with_unsupported_ecosystem(self):
        col = MagicMock()
        col.find.return_value = []
        with patch("scanner_core.helpers.cve_finder.get_cve_collection", return_value=col):
            result = bulk_find_vulnerabilities(
                [{"moduleName": "somepkg", "versionInfo": "1.0", "packageManager": "cargo"}]
            )
        assert result == {}

    def test_matches_osv_hit_within_vulnerable_range(self):
        col = MagicMock()
        col.find_one.return_value = None  # no KEV/GHSA doc for this CVE
        osv_doc = {
            "id": "CVE-2024-1111",
            "source": "osv",
            "aliases": [],
            "affected": [
                {
                    "package": {"name": "flask", "ecosystem": "PyPI"},
                    "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}],
                }
            ],
        }

        def _find(query, *args, **kwargs):
            if query.get("source") == "osv":
                return [osv_doc]
            return []

        col.find.side_effect = _find

        with patch("scanner_core.helpers.cve_finder.get_cve_collection", return_value=col):
            with patch("scanner_core.helpers.cve_finder.fetch_epss_scores", return_value={}):
                result = bulk_find_vulnerabilities(
                    [{"moduleName": "flask", "versionInfo": "1.0.0", "packageManager": "pypi"}]
                )

        vulns = result[("flask", "pypi")]
        assert len(vulns) == 1
        assert vulns[0]["cve_id"] == "CVE-2024-1111"

    def test_excludes_osv_hit_outside_vulnerable_range(self):
        col = MagicMock()
        osv_doc = {
            "id": "CVE-2024-1111",
            "source": "osv",
            "aliases": [],
            "affected": [
                {
                    "package": {"name": "flask", "ecosystem": "PyPI"},
                    "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}],
                }
            ],
        }
        col.find.return_value = [osv_doc]

        with patch("scanner_core.helpers.cve_finder.get_cve_collection", return_value=col):
            with patch("scanner_core.helpers.cve_finder.fetch_epss_scores", return_value={}):
                result = bulk_find_vulnerabilities(
                    [{"moduleName": "flask", "versionInfo": "3.0.0", "packageManager": "pypi"}]
                )

        assert result[("flask", "pypi")] == []

    def test_dedupes_repeated_dependency_by_first_occurrence(self):
        col = MagicMock()
        col.find.return_value = []

        with patch("scanner_core.helpers.cve_finder.get_cve_collection", return_value=col):
            with patch("scanner_core.helpers.cve_finder.fetch_epss_scores", return_value={}):
                result = bulk_find_vulnerabilities(
                    [
                        {"moduleName": "flask", "versionInfo": "1.0.0", "packageManager": "pypi"},
                        {"moduleName": "Flask", "versionInfo": "9.9.9", "packageManager": "pypi"},
                    ]
                )

        assert list(result.keys()) == [("flask", "pypi")]
