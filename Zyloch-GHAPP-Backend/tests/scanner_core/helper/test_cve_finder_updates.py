from __future__ import annotations

from pathlib import Path
from typing import Any, Dict
from unittest.mock import MagicMock, patch

import pytest

from scanner_core.helpers.cve_finder import (
    _doc_to_vuln,
    _extract_java_imports,
    _extract_js_requires,
    _extract_python_imports_from_source,
    _go_import_matches,
    _java_import_matches,
    _match_pypi_import,
    _oss_risk_label,
    _pkg_name_to_import_names,
    _risk_score,
    _version_in_range,
    analyze_reachability,
)


# ---------------------------------------------------------------------------
# 1. Numeric OSS risk score
# ---------------------------------------------------------------------------


class TestRiskScore:
    def test_no_signals_lands_at_unknown_reachability_floor(self):
        # cvss/epss/kev all absent, reachability defaults to the UNKNOWN
        # weight (0.50) via the mapping's None key -> 0.2 * 0.50 = 0.10.
        assert _risk_score(cvss=None, epss=None, in_kev=False, reachability=None) == 0.10

    def test_scales_with_cvss_and_epss_when_not_reachable_flagged(self):
        score = _risk_score(cvss=5.5, epss=0.3, in_kev=False, reachability="POTENTIALLY_REACHABLE")
        # 0.40*0.55 + 0.40*0.30 + 0.20*0.60 = 0.22 + 0.12 + 0.12
        assert score == pytest.approx(0.46)

    def test_kev_dominates_epss_in_exploit_component(self):
        # epss alone (0.2) vs kev (1.0): kev must win the max().
        with_kev = _risk_score(cvss=0.0, epss=0.2, in_kev=True, reachability="POTENTIALLY_REACHABLE")
        without_kev = _risk_score(cvss=0.0, epss=0.2, in_kev=False, reachability="POTENTIALLY_REACHABLE")
        assert with_kev > without_kev

    def test_not_reachable_halves_score_when_not_in_kev(self):
        reachable = _risk_score(cvss=9.8, epss=0.9, in_kev=False, reachability="POTENTIALLY_REACHABLE")
        not_reachable = _risk_score(cvss=9.8, epss=0.9, in_kev=False, reachability="NOT_REACHABLE")
        # 0.40*0.98 + 0.40*0.9 + 0.20*0.0 = 0.752, halved -> 0.376
        assert not_reachable == pytest.approx(0.376)
        assert not_reachable < reachable

    def test_not_reachable_is_not_halved_when_in_kev(self):
        # KEV + NOT_REACHABLE produces a numeric risk_score of 0.50 (a MEDIUM-tier number), but the label still forces HIGH because in_kev short-circuits the
        assert _risk_score(cvss=9.8, epss=0.9, in_kev=True, reachability="NOT_REACHABLE") == pytest.approx(0.792)

    def test_confirmed_reachable_critical_floors_at_065_before_epss_catches_up(self):
        # cvss_norm 0.98 > 0.9 threshold, so the 0.65 floor applies even though
        score = _risk_score(cvss=9.8, epss=None, in_kev=False, reachability="REACHABLE")
        assert score == pytest.approx(0.65)

    def test_confirmed_reachable_below_critical_bar_is_not_floored(self):
        # cvss_norm 0.75 < 0.9 threshold, so the 0.65 floor should not apply.
        score = _risk_score(cvss=7.5, epss=None, in_kev=False, reachability="REACHABLE")
        assert score < 0.65

    def test_reachable_func_also_gets_the_critical_floor(self):
        score = _risk_score(cvss=9.5, epss=None, in_kev=False, reachability="REACHABLE_FUNC")
        assert score >= 0.65

    def test_kev_floors_score_at_090_when_reachability_not_not_reachable(self):
        score = _risk_score(cvss=None, epss=None, in_kev=True, reachability="UNKNOWN")
        assert score == 0.90

    def test_kev_floor_does_not_lower_an_already_higher_score(self):
        # cvss=10, epss=1.0, kev=True, reachable -> weighted average already
        # exceeds 0.90, so max() must keep the higher computed value.
        score = _risk_score(cvss=10.0, epss=1.0, in_kev=True, reachability="REACHABLE_FUNC")
        assert score == 1.0

    @pytest.mark.parametrize("cvss,epss", [(-5.0, -1.0), (25.0, 5.0)])
    def test_cvss_and_epss_are_clamped_to_valid_ranges(self, cvss: float, epss: float):
        # Out-of-range inputs must clamp rather than blow up the formula:
        # cvss clamps to [0, 10], epss clamps to [0, 1].
        clamped = _risk_score(cvss=max(min(cvss, 10.0), 0.0), epss=max(min(epss, 1.0), 0.0), in_kev=False, reachability="UNKNOWN")
        actual = _risk_score(cvss=cvss, epss=epss, in_kev=False, reachability="UNKNOWN")
        assert actual == clamped

    def test_score_is_rounded_to_four_decimal_places(self):
        score = _risk_score(cvss=3.33, epss=0.111, in_kev=False, reachability="UNKNOWN")
        assert score == round(score, 4)

    def test_score_never_exceeds_one_or_drops_below_zero(self):
        high = _risk_score(cvss=10.0, epss=1.0, in_kev=True, reachability="REACHABLE_FUNC")
        low = _risk_score(cvss=0.0, epss=0.0, in_kev=False, reachability="NOT_REACHABLE")
        assert 0.0 <= low <= high <= 1.0


class TestOssRiskLabel:
    def test_kev_always_forces_high_regardless_of_score(self):
        assert _oss_risk_label(risk_score=0.01, in_kev=True, reachability="NOT_REACHABLE") == "HIGH"

    def test_confirmed_reachable_forces_high_regardless_of_score(self):
        assert _oss_risk_label(risk_score=0.05, in_kev=False, reachability="REACHABLE") == "HIGH"

    def test_reachable_func_forces_high_regardless_of_score(self):
        assert _oss_risk_label(risk_score=0.05, in_kev=False, reachability="REACHABLE_FUNC") == "HIGH"

    def test_potentially_reachable_does_not_force_high(self):
        # Only REACHABLE/REACHABLE_FUNC are confirmed; POTENTIALLY_REACHABLE
        # falls through to the plain score thresholds like everything else.
        assert _oss_risk_label(risk_score=0.05, in_kev=False, reachability="POTENTIALLY_REACHABLE") == "MONITOR"

    @pytest.mark.parametrize(
        "risk_score,expected",
        [
            (1.0, "HIGH"),
            (0.65, "HIGH"),
            (0.64, "MEDIUM"),
            (0.40, "MEDIUM"),
            (0.39, "LOW"),
            (0.20, "LOW"),
            (0.19, "MONITOR"),
            (0.0, "MONITOR"),
        ],
    )
    def test_maps_score_to_label_thresholds(self, risk_score: float, expected: str):
        assert _oss_risk_label(risk_score, in_kev=False, reachability="NOT_REACHABLE") == expected

    def test_kev_and_not_reachable_score_lands_medium_tier_but_label_is_still_high(self):
        
        score = _risk_score(cvss=None, epss=None, in_kev=True, reachability="NOT_REACHABLE")
        assert score == 0.50
        assert _oss_risk_label(score, in_kev=True, reachability="NOT_REACHABLE") == "HIGH"


class TestDocToVulnExposesRiskScoreFields:
    @pytest.fixture(autouse=True)
    def _no_epss_network_calls(self):
        api_response = MagicMock()
        api_response.raise_for_status.return_value = None
        api_response.json.return_value = {"data": []}
        with patch("scanner_core.helpers.cve_finder.requests.get", return_value=api_response):
            with patch("scanner_core.helpers.cve_finder.time.sleep"):
                yield

    def _col(self, kev_doc=None) -> MagicMock:
        col = MagicMock()

        def _find_one(query: Dict[str, Any], *args, **kwargs):
            if "_id" in query and str(query["_id"]).startswith("kev:"):
                return kev_doc
            return None

        col.find_one.side_effect = _find_one
        col.find.return_value = []
        return col

    def test_risk_score_and_oss_risk_present_alongside_risk_priority(self):
        doc = {
            "id": "CVE-2024-0001",
            "metrics": {"cvssMetricV31": [{"baseSeverity": "Critical", "cvssData": {"baseScore": 9.8}}]},
        }
        vuln = _doc_to_vuln(doc, self._col())
        assert "risk_score" in vuln
        assert "oss_risk" in vuln
        assert isinstance(vuln["risk_score"], float)
        assert vuln["oss_risk"] in {"HIGH", "MEDIUM", "LOW", "MONITOR"}

    def test_kev_hit_produces_high_oss_risk(self):
        doc = {"id": "CVE-2024-0002"}
        col = self._col(kev_doc={"dateAdded": "2024-01-01", "knownRansomwareCampaignUse": "Known"})
        vuln = _doc_to_vuln(doc, col)
        assert vuln["kev"] is True
        assert vuln["oss_risk"] == "HIGH"
        assert vuln["risk_score"] >= 0.90

    def test_no_signals_produces_monitor_oss_risk(self):
        vuln = _doc_to_vuln({"id": "CVE-2024-0003"}, self._col())
        assert vuln["oss_risk"] == "MONITOR"
        assert vuln["risk_score"] == 0.10


# ---------------------------------------------------------------------------
# 2. Reachability import-matching rework
# ---------------------------------------------------------------------------


class TestPkgNameToImportNamesSuffixStripping:
    @pytest.mark.parametrize(
        "pkg_name,expected_candidate",
        [
            ("foo-py", "foo"),
            ("bar-python", "bar"),
            ("baz-c", "baz"),
            ("multi-word-py", "multi_word"),
        ],
    )
    def test_strips_language_binding_suffix(self, pkg_name: str, expected_candidate: str):
        assert expected_candidate in _pkg_name_to_import_names(pkg_name)

    def test_does_not_strip_suffix_when_absent(self):
        candidates = _pkg_name_to_import_names("requests")
        assert "request" not in candidates


class TestExtractPythonImportsTopLevelOnly:
    def test_from_import_records_only_top_level_module(self):
        # Matches SecureScanner: only the top-level module is recorded, not
        # a submodule guess for the imported attribute.
        source = "from pandas import io\n"
        imports = _extract_python_imports_from_source(source)
        assert imports == {"pandas"}

    def test_wildcard_import_only_records_module_not_star(self):
        source = "from pandas import *\n"
        imports = _extract_python_imports_from_source(source)
        assert imports == {"pandas"}

    def test_plain_import_of_dotted_submodule_is_truncated_to_top_level(self):
        source = "import requests.adapters\n"
        assert _extract_python_imports_from_source(source) == {"requests"}

    def test_stdlib_submodule_import_is_still_excluded(self):
        # os.path's top-level segment ("os") is stdlib, so the whole import
        # is filtered out.
        source = "import os.path\n"
        assert _extract_python_imports_from_source(source) == set()

    def test_names_are_lowercased(self):
        source = "from Flask import Blueprint\n"
        imports = _extract_python_imports_from_source(source)
        assert imports == {"flask"}

    def test_plain_import_and_from_import_together(self):
        source = "import requests\nfrom flask import Flask\n"
        assert _extract_python_imports_from_source(source) == {"requests", "flask"}


class TestMatchPypiImport:
    """_match_pypi_import is a plain set intersection, matching SecureScanner.

    Since extraction now only ever produces top-level names, this is safe -
    but as a standalone function it does not do any dotted/prefix matching.
    """

    def test_direct_top_level_match(self):
        assert _match_pypi_import({"requests"}, {"requests"}) == {"requests"}

    def test_no_match_for_dotted_import_even_if_top_level_lines_up(self):
        # A hypothetical dotted entry ("yaml.loader") is not produced by
        # extraction anymore, but the matcher itself does no dot-splitting -
        # it is a bare intersection.
        assert _match_pypi_import({"yaml"}, {"yaml.loader"}) == set()

    def test_no_match_for_unrelated_import(self):
        assert _match_pypi_import({"flask"}, {"django"}) == set()

    def test_empty_inputs_produce_no_matches(self):
        assert _match_pypi_import(set(), {"requests"}) == set()
        assert _match_pypi_import({"requests"}, set()) == set()


class TestExtractJsRequiresTopSegmentOnly:
    """Matches SecureScanner: always takes the first '/'-separated segment,
    which collapses a scoped package to just its scope."""

    def test_scoped_import_collapses_to_scope_only(self):
        source = "import { z } from '@scope/pkg';"
        assert _extract_js_requires(source) == {"@scope"}

    def test_scoped_require_collapses_to_scope_only(self):
        source = "const z = require('@scope/pkg/sub');"
        assert _extract_js_requires(source) == {"@scope"}

    def test_unscoped_deep_import_uses_top_segment(self):
        source = "import fp from 'lodash/fp';"
        assert _extract_js_requires(source) == {"lodash"}


class TestExtractJavaImportsTwoSegmentPrefix:
    """Matches SecureScanner: only the first two dotted segments are kept,
    and static/wildcard imports are not matched by the extraction regex at
    all (known limitations inherited from the reference implementation)."""

    def test_returns_first_two_segments_not_full_path(self):
        source = "import org.apache.commons.lang3.StringUtils;\n"
        imports = _extract_java_imports(source)
        assert imports == {"org.apache"}

    def test_static_imports_are_not_extracted(self):
        # SecureScanner's regex (`^import\s+([\w.]+);`) has no `static`
        # handling, so the whole line fails to match.
        source = "import static org.junit.jupiter.api.Assertions.assertEquals;\n"
        assert _extract_java_imports(source) == set()

    def test_wildcard_imports_are_not_extracted(self):
        # Same regex gap: the trailing ".*" is not in the [\w.]+ character
        # class, so wildcard import lines fail to match entirely.
        source = "import org.apache.commons.lang3.*;\n"
        assert _extract_java_imports(source) == set()

    def test_ignores_single_segment_imports(self):
        assert _extract_java_imports("import java;\n") == set()


class TestJavaImportMatches:
    """_java_import_matches is imp.startswith(group), matching
    SecureScanner - the same direction as the reference's inline
    `imp.startswith(prefix)` check."""

    def test_exact_group_match(self):
        assert _java_import_matches("org.apache", "org.apache") is True

    def test_matches_when_import_is_nested_under_group(self):
        assert _java_import_matches("org.apache", "org.apache.commons.lang3.stringutils") is True

    def test_known_gap_matches_unrelated_group_sharing_a_string_prefix(self):
        # Known limitation inherited from SecureScanner: "org.apache2.foo"
        # is unrelated to groupId "org.apache", but plain startswith() has no dot-boundary check.
        assert _java_import_matches("org.apache", "org.apache2.foo") is True

    def test_case_insensitive_group_comparison(self):
        assert _java_import_matches("Org.Apache", "org.apache.commons") is True


class TestGoImportMatches:
    """_go_import_matches is a bare substring-or-prefix check, matching
    SecureScanner's `pkg in imp or imp.startswith(pkg)`."""

    def test_exact_match(self):
        assert _go_import_matches("github.com/gin-gonic/gin", "github.com/gin-gonic/gin") is True

    def test_matches_subpackage_under_module(self):
        assert _go_import_matches("github.com/gin-gonic/gin", "github.com/gin-gonic/gin/binding") is True

    def test_known_gap_matches_substring_without_path_boundary(self):
        # Known limitation inherited from SecureScanner: "lib" is a plain
        # substring of "library", so this is (incorrectly) a match.
        assert _go_import_matches("lib", "library") is True

    def test_does_not_match_unrelated_module(self):
        assert _go_import_matches("github.com/gin-gonic/gin", "github.com/labstack/echo") is False


class TestAnalyzeReachabilityTransitiveSubmoduleChain:
    def test_dotted_local_import_still_resolves_transitive_chain(self, tmp_path: Path):
        
        (tmp_path / "app.py").write_text("import utils.sub\n", encoding="utf-8")
        (tmp_path / "utils.py").write_text("import aiohttp\n", encoding="utf-8")
        deps = [{"moduleName": "aiohttp", "versionInfo": "3.9", "packageManager": "pypi"}]

        reach = analyze_reachability(deps, str(tmp_path))

        assert reach[("aiohttp", "pypi")] == "REACHABLE"


class TestAnalyzeReachabilityKnownGaps:
    """End-to-end cases documenting the false-match gaps intentionally
    reintroduced to match SecureScanner's reference reachability.py."""

    def test_java_group_with_similar_prefix_is_falsely_reachable(self, tmp_path: Path):
        # Known gap: "org.apache2.foo" is unrelated to groupId "org.apache",
        # but plain startswith() has no dot-boundary check.
        src = tmp_path / "src"
        src.mkdir()
        (src / "App.java").write_text("import org.apache2.foo.Bar;\n", encoding="utf-8")
        deps = [{"moduleName": "org.apache:commons", "versionInfo": "1.0", "packageManager": "maven"}]

        reach = analyze_reachability(deps, str(tmp_path))

        assert reach[("org.apache:commons", "maven")] == "REACHABLE"

    def test_scoped_npm_package_is_not_matched(self, tmp_path: Path):
        
        (tmp_path / "index.js").write_text("import { z } from '@scope/pkg';\n", encoding="utf-8")
        deps = [{"moduleName": "@scope/pkg", "versionInfo": "1.0.0", "packageManager": "npm"}]

        reach = analyze_reachability(deps, str(tmp_path))

        assert reach[("@scope/pkg", "npm")] == "NOT_REACHABLE"


# ---------------------------------------------------------------------------
# 3. Multi-segment version ranges
# ---------------------------------------------------------------------------


class TestVersionInRangeMultiSegment:
    def test_multi_segment_range_flags_version_in_earlier_release_line(self):
        
        affected = [{
            "ranges": [{
                "type": "SEMVER",
                "events": [
                    {"introduced": "0"}, {"fixed": "1.2.0"},
                    {"introduced": "2.0.0"}, {"fixed": "2.2.0"},
                ],
            }]
        }]
        assert _version_in_range("1.0.0", affected) is True

    def test_multi_segment_range_excludes_version_between_release_lines(self):
        # 1.5.0 is patched in the first line (>= 1.2.0 fix) and not yet
        # reached by the second line (< 2.0.0 introduced) - genuinely safe.
        affected = [{
            "ranges": [{
                "type": "SEMVER",
                "events": [
                    {"introduced": "0"}, {"fixed": "1.2.0"},
                    {"introduced": "2.0.0"}, {"fixed": "2.2.0"},
                ],
            }]
        }]
        assert _version_in_range("1.5.0", affected) is False

    def test_multi_segment_range_flags_version_in_second_release_line(self):
        affected = [{
            "ranges": [{
                "type": "SEMVER",
                "events": [
                    {"introduced": "0"}, {"fixed": "1.2.0"},
                    {"introduced": "2.0.0"}, {"fixed": "2.2.0"},
                ],
            }]
        }]
        assert _version_in_range("2.1.0", affected) is True
