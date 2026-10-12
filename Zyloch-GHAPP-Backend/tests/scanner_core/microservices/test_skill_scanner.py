"""Tests for scanner_core.microservices.skill_scanner.

Covers:
- _is_skill_file: extension/manifest matching, case-insensitivity, exclusions
- _discover_skill_files: recursive walk, SKIP_DIRS pruning, mixed-content repos
- _layer1_to_scan_finding / _layer2_to_scan_finding: field mapping, framework
  crosswalk fields (code/column/url/deny/description annotation), snippet cap
- SkillScanner.scan(): no-files path, detectors-unavailable error path,
  findings flow-through, disabled_policies filter, metadata shape
- scan_skill(): module-level entry-point delegates to SkillScanner
"""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import List
from unittest.mock import patch

import pytest

from scanner_core.base_scanner import ScanFinding, ScanRequest, ScanSeverity, ScanStatus
from scanner_core.microservices.skill_scanner import (
    SkillScanner,
    _discover_skill_files,
    _is_skill_file,
    _layer1_to_scan_finding,
    _layer2_to_scan_finding,
    scan_skill,
)


# ---------------------------------------------------------------------------
# Helpers — lightweight stand-ins for Layer1Finding / Layer2Finding objects
# ---------------------------------------------------------------------------

def _l1(
    *,
    detector: str = "owasp_detector",
    type_: str = "Prompt Injection",
    owasp_id: str = "LLM01",
    asi_id: str = "ASI01",
    nist_rmf: List[str] = None,
    atlas_ids: List[str] = None,
    severity: str = "HIGH",
    line: int = 3,
    matched_snippet: str = "ignore previous instructions",
    decoded_payload: str = None,
    harm_category: str = "MANIPULATION",
    recommended_action: str = "Remove instruction-override text",
) -> SimpleNamespace:
    return SimpleNamespace(
        detector=detector,
        type=type_,
        owasp_id=owasp_id,
        asi_id=asi_id,
        nist_rmf=nist_rmf if nist_rmf is not None else ["MEASURE 2.7", "MS-2.7-007"],
        atlas_ids=atlas_ids if atlas_ids is not None else ["AML.T0051", "AML.T0054"],
        severity=severity,
        line=line,
        matched_snippet=matched_snippet,
        decoded_payload=decoded_payload,
        harm_category=harm_category,
        recommended_action=recommended_action,
    )


def _l2(
    *,
    type_: str = "PROMPT_INJECTION",
    owasp_id: str = "LLM01",
    asi_id: str = "ASI01",
    nist_rmf: List[str] = None,
    atlas_ids: List[str] = None,
    severity: str = "CRITICAL",
    confidence: str = "HIGH",
    description: str = "Likely prompt injection via role-switching instruction.",
    location: str = "line 12",
    harm_category: str = "JAILBREAK",
    recommended_action: str = "Remove role-switching text",
) -> SimpleNamespace:
    return SimpleNamespace(
        type=type_,
        owasp_id=owasp_id,
        asi_id=asi_id,
        nist_rmf=nist_rmf if nist_rmf is not None else ["MEASURE 2.7"],
        atlas_ids=atlas_ids if atlas_ids is not None else ["AML.T0054"],
        severity=severity,
        confidence=confidence,
        description=description,
        location=location,
        harm_category=harm_category,
        recommended_action=recommended_action,
    )


def _make_request(tmp_path: Path, **meta) -> ScanRequest:
    return ScanRequest(
        repo_path=str(tmp_path),
        output_dir=str(tmp_path / "output"),
        scan_id="test-scan-001",
        metadata=meta if meta else None,
    )


# ---------------------------------------------------------------------------
# _is_skill_file
# ---------------------------------------------------------------------------

class TestIsSkillFile:

    @pytest.mark.parametrize("name", [
        "SKILL.md", "claude.md", "README.md", "malicious.md", "rules.md",
    ])
    def test_markdown_files_accepted(self, name: str):
        assert _is_skill_file(Path(name)) is True

    @pytest.mark.parametrize("name", [
        "page.html", "SKILL.html", "payload.HTML", "index.htm",
    ])
    def test_html_variants_accepted(self, name: str):
        assert _is_skill_file(Path(name)) is True

    @pytest.mark.parametrize("name", [
        "plugin.json", "mcp.json", ".mcp.json",
    ])
    def test_manifest_files_accepted(self, name: str):
        assert _is_skill_file(Path(name)) is True

    @pytest.mark.parametrize("name", [
        "hooks.json", "package.json", "settings.json",
        "helper.py", "setup.sh", "Dockerfile", "requirements.txt",
        "image.png", ".cursorrules",   # no extension → not matched
    ])
    def test_non_skill_files_rejected(self, name: str):
        assert _is_skill_file(Path(name)) is False

    def test_md_anywhere_in_tree_accepted(self):
        assert _is_skill_file(Path("some/deep/subdir/agent.md")) is True

    def test_html_anywhere_in_tree_accepted(self):
        assert _is_skill_file(Path("commands/deploy.html")) is True

    def test_extension_check_is_case_insensitive(self):
        assert _is_skill_file(Path("SKILL.MD")) is True
        assert _is_skill_file(Path("page.HTML")) is True
        assert _is_skill_file(Path("page.HTM")) is True


# ---------------------------------------------------------------------------
# _discover_skill_files
# ---------------------------------------------------------------------------

class TestDiscoverSkillFiles:

    def test_finds_markdown_files_at_root(self, tmp_path: Path):
        (tmp_path / "SKILL.md").write_text("# Skill")
        (tmp_path / "README.md").write_text("# Readme")
        names = {p.name for p in _discover_skill_files(str(tmp_path))}
        assert {"SKILL.md", "README.md"} <= names

    def test_finds_html_files(self, tmp_path: Path):
        (tmp_path / "payload.html").write_text("<html></html>")
        assert any(p.name == "payload.html" for p in _discover_skill_files(str(tmp_path)))

    def test_finds_manifest_files(self, tmp_path: Path):
        (tmp_path / "plugin.json").write_text("{}")
        (tmp_path / "mcp.json").write_text("{}")
        names = {p.name for p in _discover_skill_files(str(tmp_path))}
        assert {"plugin.json", "mcp.json"} <= names

    def test_finds_nested_skill_files(self, tmp_path: Path):
        nested = tmp_path / ".claude" / "agents"
        nested.mkdir(parents=True)
        (nested / "code-reviewer.md").write_text("# Agent")
        assert any(p.name == "code-reviewer.md" for p in _discover_skill_files(str(tmp_path)))

    def test_skips_git_directory(self, tmp_path: Path):
        git_dir = tmp_path / ".git" / "hooks"
        git_dir.mkdir(parents=True)
        (git_dir / "pre-commit.md").write_text("skip me")
        (tmp_path / "SKILL.md").write_text("keep me")
        result = _discover_skill_files(str(tmp_path))
        assert not any(".git" in str(p) for p in result)
        assert any(p.name == "SKILL.md" for p in result)

    def test_skips_node_modules(self, tmp_path: Path):
        nm = tmp_path / "node_modules" / "some-pkg"
        nm.mkdir(parents=True)
        (nm / "README.md").write_text("pkg readme")
        assert not any("node_modules" in str(p) for p in _discover_skill_files(str(tmp_path)))

    def test_skips_build_and_dist_dirs(self, tmp_path: Path):
        for skip_dir in ("build", "dist"):
            d = tmp_path / skip_dir
            d.mkdir()
            (d / "artifact.md").write_text("artifact")
        (tmp_path / "SKILL.md").write_text("real skill")
        result = _discover_skill_files(str(tmp_path))
        names = [p.name for p in result]
        assert "artifact.md" not in names
        assert "SKILL.md" in names

    def test_excludes_non_skill_extensions(self, tmp_path: Path):
        (tmp_path / "helper.py").write_text("import os")
        (tmp_path / "config.yaml").write_text("key: value")
        (tmp_path / "hooks.json").write_text("{}")
        names = {p.name for p in _discover_skill_files(str(tmp_path))}
        assert "helper.py" not in names
        assert "config.yaml" not in names
        assert "hooks.json" not in names

    def test_empty_repo_returns_empty_list(self, tmp_path: Path):
        assert _discover_skill_files(str(tmp_path)) == []

    def test_returns_absolute_paths(self, tmp_path: Path):
        (tmp_path / "agent.md").write_text("# Agent")
        assert all(p.is_absolute() for p in _discover_skill_files(str(tmp_path)))


# ---------------------------------------------------------------------------
# _layer1_to_scan_finding
# ---------------------------------------------------------------------------

class TestLayer1ToScanFinding:

    def test_policy_uses_detector_and_type(self):
        sf = _layer1_to_scan_finding(_l1(detector="owasp_detector", type_="Prompt Injection"), "SKILL.md")
        assert sf.policy == "owasp_detector:Prompt Injection"

    def test_policy_falls_back_to_type_when_no_detector(self):
        sf = _layer1_to_scan_finding(_l1(detector="", type_="TOKEN_MERGE_INJECTION"), "SKILL.md")
        assert sf.policy == "TOKEN_MERGE_INJECTION"

    def test_owasp_id_in_code_field(self):
        assert _layer1_to_scan_finding(_l1(owasp_id="LLM01"), "f.md").code == "LLM01"

    def test_asi_id_in_column_field(self):
        assert _layer1_to_scan_finding(_l1(asi_id="ASI03"), "f.md").column == "ASI03"

    def test_nist_rmf_in_url_field(self):
        sf = _layer1_to_scan_finding(_l1(nist_rmf=["MEASURE 2.7", "MAP 4.2"]), "f.md")
        assert sf.url == "MEASURE 2.7 | MAP 4.2"

    def test_atlas_ids_in_deny_field(self):
        sf = _layer1_to_scan_finding(_l1(atlas_ids=["AML.T0051", "AML.T0054"]), "f.md")
        assert sf.deny == ["AML.T0051", "AML.T0054"]

    @pytest.mark.parametrize("raw,expected", [
        ("CRITICAL", ScanSeverity.CRITICAL),
        ("HIGH",     ScanSeverity.HIGH),
        ("MEDIUM",   ScanSeverity.MEDIUM),
        ("LOW",      ScanSeverity.LOW),
        ("UNKNOWN",  ScanSeverity.LOW),  # fallback
    ])
    def test_severity_mapping(self, raw: str, expected: ScanSeverity):
        assert _layer1_to_scan_finding(_l1(severity=raw), "f.md").severity == expected

    def test_matched_snippet_in_match_field(self):
        assert _layer1_to_scan_finding(_l1(matched_snippet="bad text"), "f.md").match == "bad text"

    def test_decoded_payload_used_when_no_snippet(self):
        finding = _l1(matched_snippet=None, decoded_payload="<decoded>")
        assert _layer1_to_scan_finding(finding, "f.md").match == "<decoded>"

    def test_match_truncated_at_500_chars(self):
        sf = _layer1_to_scan_finding(_l1(matched_snippet="x" * 600), "f.md")
        assert len(sf.match) == 500

    def test_line_converted_to_string(self):
        assert _layer1_to_scan_finding(_l1(line=42), "f.md").line == "42"

    def test_line_none_stays_none(self):
        f = _l1()
        f.line = None
        assert _layer1_to_scan_finding(f, "f.md").line is None

    def test_file_path_preserved(self):
        assert _layer1_to_scan_finding(_l1(), "agents/code-reviewer.md").file == "agents/code-reviewer.md"

    def test_description_contains_owasp_id(self):
        assert "[LLM01]" in _layer1_to_scan_finding(_l1(owasp_id="LLM01"), "f.md").description

    def test_description_contains_framework_annotation(self):
        sf = _layer1_to_scan_finding(
            _l1(asi_id="ASI01", nist_rmf=["MEASURE 2.7"], atlas_ids=["AML.T0051"]), "f.md"
        )
        assert "ASI01" in sf.description
        assert "NIST:" in sf.description
        assert "ATLAS:" in sf.description

    def test_no_framework_fields_no_annotation(self):
        # Use an unmapped type/owasp_id so the direct-lookup fallback also
        # returns None and no framework annotation is appended.
        finding = _l1(type_="UNMAPPED_RULE", owasp_id=None, asi_id=None, nist_rmf=[], atlas_ids=[])
        sf = _layer1_to_scan_finding(finding, "f.md")
        assert "ASI" not in sf.description
        assert "NIST" not in sf.description
        assert "ATLAS" not in sf.description

    def test_no_url_when_nist_empty(self):
        # Unmapped type ensures no fallback lookup fills in NIST controls.
        assert _layer1_to_scan_finding(_l1(type_="UNMAPPED_RULE", owasp_id=None, nist_rmf=[]), "f.md").url is None

    def test_no_deny_when_atlas_empty(self):
        # Unmapped type ensures no fallback lookup fills in ATLAS IDs.
        assert _layer1_to_scan_finding(_l1(type_="UNMAPPED_RULE", owasp_id=None, atlas_ids=[]), "f.md").deny is None


# ---------------------------------------------------------------------------
# _layer2_to_scan_finding
# ---------------------------------------------------------------------------

class TestLayer2ToScanFinding:

    def test_policy_prefixed_with_llm(self):
        assert _layer2_to_scan_finding(_l2(type_="JAILBREAK_ATTEMPT"), "f.md").policy == "llm:JAILBREAK_ATTEMPT"

    def test_harm_category_prepended_to_description(self):
        assert _layer2_to_scan_finding(_l2(harm_category="EXFILTRATION"), "f.md").description.startswith("[EXFILTRATION]")

    def test_owasp_id_in_code(self):
        assert _layer2_to_scan_finding(_l2(owasp_id="LLM02"), "f.md").code == "LLM02"

    def test_asi_id_in_column(self):
        assert _layer2_to_scan_finding(_l2(asi_id="ASI04"), "f.md").column == "ASI04"

    def test_nist_rmf_in_url(self):
        sf = _layer2_to_scan_finding(_l2(nist_rmf=["MAP 4.1", "MANAGE 3.1"]), "f.md")
        assert sf.url == "MAP 4.1 | MANAGE 3.1"

    def test_atlas_ids_in_deny(self):
        sf = _layer2_to_scan_finding(_l2(atlas_ids=["AML.T0025", "AML.T0024"]), "f.md")
        assert sf.deny == ["AML.T0025", "AML.T0024"]

    def test_location_mapped_to_line(self):
        assert _layer2_to_scan_finding(_l2(location="line 7"), "f.md").line == "line 7"

    def test_none_location_gives_none_line(self):
        f = _l2()
        f.location = None
        assert _layer2_to_scan_finding(f, "f.md").line is None

    def test_framework_annotation_in_description(self):
        sf = _layer2_to_scan_finding(
            _l2(asi_id="ASI01", nist_rmf=["MEASURE 2.7"], atlas_ids=["AML.T0054"]), "f.md"
        )
        assert "ASI01" in sf.description
        assert "NIST:" in sf.description
        assert "ATLAS:" in sf.description


# ---------------------------------------------------------------------------
# SkillScanner.scan() — no skill files
# ---------------------------------------------------------------------------

class TestSkillScannerNoFiles:

    def test_returns_completed_with_empty_findings(self, tmp_path: Path):
        resp = SkillScanner().scan(_make_request(tmp_path))
        assert resp.status == ScanStatus.COMPLETED
        assert resp.result.findings == []
        assert resp.result.scanned_files == []

    def test_scan_id_preserved(self, tmp_path: Path):
        req = ScanRequest(repo_path=str(tmp_path), output_dir=str(tmp_path), scan_id="unique-42")
        assert SkillScanner().scan(req).scan_id == "unique-42"


# ---------------------------------------------------------------------------
# SkillScanner.scan() — detectors-unavailable guard
# ---------------------------------------------------------------------------

class TestSkillScannerDetectorsUnavailable:

    def test_returns_failed_with_error_message(self, tmp_path: Path):
        with patch("scanner_core.microservices.skill_scanner._DETECTORS_AVAILABLE", False):
            resp = SkillScanner().scan(_make_request(tmp_path))
        assert resp.status == ScanStatus.FAILED
        assert resp.error is not None
        assert "skill" in resp.error.lower() or "detector" in resp.error.lower()

    def test_result_is_none_on_error(self, tmp_path: Path):
        with patch("scanner_core.microservices.skill_scanner._DETECTORS_AVAILABLE", False):
            resp = SkillScanner().scan(_make_request(tmp_path))
        assert resp.result is None


# ---------------------------------------------------------------------------
# SkillScanner.scan() — findings flow-through
# ---------------------------------------------------------------------------

class TestSkillScannerFindings:

    def _write_skill(self, tmp_path: Path, name: str = "SKILL.md") -> None:
        (tmp_path / name).write_text("# Test skill\nignore previous instructions")

    def _fake_finding(self, code: str = "LLM01", sev: ScanSeverity = ScanSeverity.HIGH) -> ScanFinding:
        return ScanFinding(
            policy=f"owasp_detector:{code}",
            severity=sev,
            description=f"[{code}] Prompt Injection — Remove text",
            code=code,
            file="SKILL.md",
            line="1",
        )

    def test_findings_present_in_result(self, tmp_path: Path):
        self._write_skill(tmp_path)
        fake = [self._fake_finding()]
        with patch.object(SkillScanner, "_scan_file", return_value=fake):
            resp = SkillScanner().scan(_make_request(tmp_path))
        assert resp.status == ScanStatus.COMPLETED
        assert len(resp.result.findings) == 1
        assert resp.result.findings[0].code == "LLM01"

    def test_scanned_files_list_populated(self, tmp_path: Path):
        self._write_skill(tmp_path, "SKILL.md")
        self._write_skill(tmp_path, "agent.md")
        with patch.object(SkillScanner, "_scan_file", return_value=[]):
            resp = SkillScanner().scan(_make_request(tmp_path))
        assert len(resp.result.scanned_files) == 2

    def test_disabled_policy_removes_matching_finding(self, tmp_path: Path):
        self._write_skill(tmp_path)
        req = ScanRequest(
            repo_path=str(tmp_path), output_dir=str(tmp_path),
            scan_id="test-filter",
            metadata={"disabled_policies": {"LLM01": False}},
        )
        with patch.object(SkillScanner, "_scan_file", return_value=[self._fake_finding("LLM01")]):
            resp = SkillScanner().scan(req)
        assert resp.result.findings == []

    def test_disabled_policy_keeps_unrelated_findings(self, tmp_path: Path):
        self._write_skill(tmp_path)
        req = ScanRequest(
            repo_path=str(tmp_path), output_dir=str(tmp_path),
            scan_id="test-partial",
            metadata={"disabled_policies": {"LLM01": False}},
        )
        fake = [self._fake_finding("LLM01"), self._fake_finding("LLM06")]
        with patch.object(SkillScanner, "_scan_file", return_value=fake):
            resp = SkillScanner().scan(req)
        assert len(resp.result.findings) == 1
        assert resp.result.findings[0].code == "LLM06"

    def test_metadata_contains_framework_list(self, tmp_path: Path):
        self._write_skill(tmp_path)
        with patch.object(SkillScanner, "_scan_file", return_value=[]):
            resp = SkillScanner().scan(_make_request(tmp_path))
        fw = resp.result.metadata.get("frameworks", [])
        assert any("NIST" in f for f in fw)
        assert any("ATLAS" in f for f in fw)
        assert any("OWASP" in f for f in fw)

    def test_metadata_severity_breakdown(self, tmp_path: Path):
        self._write_skill(tmp_path)
        fake = [
            self._fake_finding(sev=ScanSeverity.HIGH),
            self._fake_finding(sev=ScanSeverity.HIGH),
            self._fake_finding(sev=ScanSeverity.CRITICAL),
        ]
        with patch.object(SkillScanner, "_scan_file", return_value=fake):
            resp = SkillScanner().scan(_make_request(tmp_path))
        breakdown = resp.result.metadata.get("severity_breakdown", {})
        assert breakdown.get("high") == 2
        assert breakdown.get("critical") == 1

    def test_metadata_total_skill_files_count(self, tmp_path: Path):
        for i in range(3):
            (tmp_path / f"skill{i}.md").write_text("# Skill")
        with patch.object(SkillScanner, "_scan_file", return_value=[]):
            resp = SkillScanner().scan(_make_request(tmp_path))
        assert resp.result.metadata["total_skill_files"] == 3

    def test_scanner_type_is_skill_scanner(self, tmp_path: Path):
        with patch.object(SkillScanner, "_scan_file", return_value=[]):
            resp = SkillScanner().scan(_make_request(tmp_path))
        assert resp.scanner_type == "skill_scanner"
        assert resp.result.scanner_type == "skill_scanner"


# ---------------------------------------------------------------------------
# scan_skill() module-level entry point
# ---------------------------------------------------------------------------

class TestScanSkillFunction:

    def test_delegates_to_skill_scanner(self, tmp_path: Path):
        resp = scan_skill(_make_request(tmp_path))
        assert resp.scan_id == "test-scan-001"
        assert resp.scanner_type == "skill_scanner"

    def test_returns_scan_response_type(self, tmp_path: Path):
        from scanner_core.base_scanner import ScanResponse
        assert isinstance(scan_skill(_make_request(tmp_path)), ScanResponse)
