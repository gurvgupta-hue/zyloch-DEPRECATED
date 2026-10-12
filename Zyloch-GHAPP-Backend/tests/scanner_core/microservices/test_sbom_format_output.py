"""SBOM tests: SPDX/CycloneDX stacks, statistics, and findings."""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from scanner_core.microservices.sbom_scanner import (
    SBOMScanner,
    _build_go_url,
    _build_maven_url,
    _build_npm_url,
    _build_pypi_url,
)


@pytest.fixture
def scanner() -> SBOMScanner:
    return SBOMScanner()


class TestBuildSbomFormattedOutput:
    def test_spdx_and_cyclonedx_stacks_on_dependency(self, scanner: SBOMScanner):
        deps = [
            {
                "moduleName": "requests",
                "versionInfo": "2.31.0",
                "packageManager": "pypi",
                "licenseConcluded": "MIT",
                "sha": "abc123",
                "sourceLocation": "requirements.txt",
                "packageURL": _build_pypi_url("requests"),
            }
        ]
        result = scanner._build_sbom_formatted_output(deps)

        assert len(result) == 1
        entry = result[0]
        assert entry["name"] == "requests"
        assert entry["version"] == "2.31.0"
        assert entry["ecosystem"] == "pypi"
        assert entry["license"] == "MIT"
        assert entry["purl"] == "pkg:pypi/requests@2.31.0"
        assert entry["stacks"]["spdx"]["id"].startswith("SPDXRef-Package-0-")
        assert entry["stacks"]["spdx"]["download_location"] == _build_pypi_url("requests")
        assert entry["stacks"]["spdx"]["files_analyzed"] is False
        assert entry["stacks"]["cyclonedx"]["type"] == "library"
        assert "bom_ref" in entry["stacks"]["cyclonedx"]

    def test_go_ecosystem_maps_to_golang_purl(self, scanner: SBOMScanner):
        dep = {
            "moduleName": "github.com/gin-gonic/gin",
            "versionInfo": "1.9.0",
            "packageManager": "go",
            "licenseConcluded": "MIT",
            "sha": "sha1",
            "sourceLocation": "go.mod",
            "packageURL": _build_go_url("github.com/gin-gonic/gin"),
        }
        entry = scanner._build_sbom_formatted_output([dep])[0]
        # Go module versions are always "v"-prefixed, matching Go's own convention.
        assert entry["purl"] == "pkg:golang/github.com/gin-gonic/gin@v1.9.0"

    def test_go_purl_does_not_double_prefix_already_v_prefixed_version(
        self, scanner: SBOMScanner
    ):
        dep = {
            "moduleName": "golang.org/x/image",
            "versionInfo": "v0.44.0",
            "packageManager": "go",
            "licenseConcluded": "BSD-3-Clause",
            "sha": "sha1",
            "sourceLocation": "go.mod",
            "packageURL": _build_go_url("golang.org/x/image"),
        }
        entry = scanner._build_sbom_formatted_output([dep])[0]
        assert entry["purl"] == "pkg:golang/golang.org/x/image@v0.44.0"

    def test_non_go_ecosystems_do_not_get_v_prefix(self, scanner: SBOMScanner):
        dep = {
            "moduleName": "requests",
            "versionInfo": "2.31.0",
            "packageManager": "pypi",
            "licenseConcluded": "MIT",
            "sha": "abc",
            "sourceLocation": "requirements.txt",
            "packageURL": _build_pypi_url("requests"),
        }
        entry = scanner._build_sbom_formatted_output([dep])[0]
        assert entry["purl"] == "pkg:pypi/requests@2.31.0"

    def test_gradle_maps_to_maven_purl_eco(self, scanner: SBOMScanner):
        dep = {
            "moduleName": "com.google.guava:guava",
            "versionInfo": "33.0.0",
            "packageManager": "gradle",
            "licenseConcluded": "Apache-2.0",
            "sha": "abc",
            "sourceLocation": "build.gradle",
            "packageURL": _build_maven_url("com.google.guava:guava"),
        }
        entry = scanner._build_sbom_formatted_output([dep])[0]
        assert entry["purl"].startswith("pkg:maven/")

    def test_purl_omits_version_when_none(self, scanner: SBOMScanner):
        dep = {
            "moduleName": "requests",
            "versionInfo": None,
            "packageManager": "pypi",
            "licenseConcluded": "-",
            "sha": "Unknown",
            "sourceLocation": "requirements.txt",
            "packageURL": _build_pypi_url("requests"),
        }
        entry = scanner._build_sbom_formatted_output([dep])[0]
        assert entry["purl"] == "pkg:pypi/requests"
        assert "@" not in entry["purl"]

    def test_multiple_packages_have_unique_spdx_ids(self, scanner: SBOMScanner):
        deps = [
            {
                "moduleName": "pkgA",
                "versionInfo": "1.0",
                "packageManager": "pypi",
                "licenseConcluded": "MIT",
                "sha": "s1",
                "sourceLocation": "requirements.txt",
                "packageURL": _build_pypi_url("pkgA"),
            },
            {
                "moduleName": "pkgB",
                "versionInfo": "2.0",
                "packageManager": "npm",
                "licenseConcluded": "ISC",
                "sha": "s2",
                "sourceLocation": "package.json",
                "packageURL": _build_npm_url("pkgB"),
            },
        ]
        result = scanner._build_sbom_formatted_output(deps)
        ids = [e["stacks"]["spdx"]["id"] for e in result]
        assert ids[0] != ids[1]
        assert "SPDXRef-Package-0-pkgA" in ids[0]
        assert "SPDXRef-Package-1-pkgB" in ids[1]

    def test_download_location_uses_registry_url_when_available(self, scanner: SBOMScanner):
        dep = {
            "moduleName": "lodash",
            "versionInfo": "4.17.21",
            "packageManager": "npm",
            "licenseConcluded": "MIT",
            "sha": "abc123",
            "sourceLocation": "package.json",
            "packageURL": _build_npm_url("lodash"),
        }
        entry = scanner._build_sbom_formatted_output([dep])[0]
        assert entry["stacks"]["spdx"]["download_location"] == _build_npm_url("lodash")

    def test_download_location_falls_back_to_noassertion_when_no_url(self, scanner: SBOMScanner):
        dep = {
            "moduleName": "internal-lib",
            "versionInfo": "1.0.0",
            "packageManager": "unknown",
            "licenseConcluded": "-",
            "sha": "Unknown",
            "sourceLocation": "lockfile",
            "packageURL": "Unknown",
        }
        entry = scanner._build_sbom_formatted_output([dep])[0]
        assert entry["stacks"]["spdx"]["download_location"] == "NOASSERTION"

    @pytest.mark.parametrize(
        "manager,name,version,expected",
        [
            ("pypi", "requests", "2.31.0", "https://pypi.org/project/requests/2.31.0/"),
            ("npm", "lodash", "4.17.21", "https://www.npmjs.com/package/lodash/v/4.17.21"),
            ("go", "golang.org/x/image", "0.44.0", "https://pkg.go.dev/golang.org/x/image@v0.44.0"),
            (
                "maven",
                "com.google.guava:guava",
                "33.0.0",
                "https://mvnrepository.com/artifact/com.google.guava/guava/33.0.0",
            ),
        ],
    )
    def test_download_location_fallback_is_version_specific_per_ecosystem(
        self, scanner: SBOMScanner, manager, name, version, expected
    ):
        # No packageURL given at all - _build_sbom_formatted_output must build
        # its own version-specific fallback rather than the bare project page.
        dep = {
            "moduleName": name,
            "versionInfo": version,
            "packageManager": manager,
            "licenseConcluded": "-",
            "sha": "Unknown",
            "sourceLocation": "lockfile",
        }
        entry = scanner._build_sbom_formatted_output([dep])[0]
        assert entry["stacks"]["spdx"]["download_location"] == expected

    def test_files_analyzed_defaults_false(self, scanner: SBOMScanner):
        dep = {
            "moduleName": "flask",
            "versionInfo": "3.0.0",
            "packageManager": "pypi",
            "licenseConcluded": "BSD-3-Clause",
            "sha": "deadbeef",
            "sourceLocation": "requirements.txt",
            "packageURL": _build_pypi_url("flask"),
        }
        entry = scanner._build_sbom_formatted_output([dep])[0]
        assert entry["stacks"]["spdx"]["files_analyzed"] is False

    def test_files_analyzed_false_when_sha_unknown(self, scanner: SBOMScanner):
        dep = {
            "moduleName": "flask",
            "versionInfo": "3.0.0",
            "packageManager": "pypi",
            "licenseConcluded": "-",
            "sha": "Unknown",
            "sourceLocation": "requirements.txt",
            "packageURL": _build_pypi_url("flask"),
        }
        entry = scanner._build_sbom_formatted_output([dep])[0]
        assert entry["stacks"]["spdx"]["files_analyzed"] is False

    def test_sha_and_source_file_carried_through(self, scanner: SBOMScanner):
        dep = {
            "moduleName": "django",
            "versionInfo": "5.0.0",
            "packageManager": "pypi",
            "licenseConcluded": "BSD-3-Clause",
            "sha": "deadbeef1234",
            "sourceLocation": "backend/requirements.txt",
            "packageURL": _build_pypi_url("django"),
        }
        entry = scanner._build_sbom_formatted_output([dep])[0]
        assert entry["sha"] == "deadbeef1234"
        assert entry["source_file"] == "backend/requirements.txt"


class TestCalculateStatistics:
    def test_unknown_license_triggers_legal_review(self, scanner: SBOMScanner):
        deps = [
            {"moduleName": "a", "packageManager": "pypi", "licenseConcluded": "-"},
            {"moduleName": "b", "packageManager": "pypi", "licenseConcluded": "MIT"},
        ]
        stats = scanner._calculate_statistics(deps)

        assert stats["total_packages"] == 2
        assert stats["total_package_managers"] == 1
        assert stats["unique_license_types"] == 1
        assert stats["unknown_licenses_count"] == 1
        assert stats["legal_review_required"] is True

    def test_all_known_licenses_no_legal_review(self, scanner: SBOMScanner):
        deps = [
            {"moduleName": "a", "packageManager": "pypi", "licenseConcluded": "MIT"},
            {"moduleName": "b", "packageManager": "npm", "licenseConcluded": "Apache-2.0"},
        ]
        stats = scanner._calculate_statistics(deps)

        assert stats["unknown_licenses_count"] == 0
        assert stats["legal_review_required"] is False
        assert stats["total_package_managers"] == 2

    def test_empty_deps_returns_all_zeros(self, scanner: SBOMScanner):
        stats = scanner._calculate_statistics([])
        assert stats["total_packages"] == 0
        assert stats["total_package_managers"] == 0
        assert stats["unique_license_types"] == 0
        assert stats["unknown_licenses_count"] == 0
        assert stats["legal_review_required"] is False

    def test_noassertion_counted_as_unknown(self, scanner: SBOMScanner):
        deps = [{"moduleName": "a", "packageManager": "pypi", "licenseConcluded": "NOASSERTION"}]
        stats = scanner._calculate_statistics(deps)
        assert stats["unknown_licenses_count"] == 1
        assert stats["unique_license_types"] == 0

    def test_license_list_uses_first_element(self, scanner: SBOMScanner):
        dep = {"moduleName": "a", "packageManager": "pypi", "licenseConcluded": ["MIT", "Apache-2.0"]}
        stats = scanner._calculate_statistics([dep])
        assert stats["unique_license_types"] == 1
        assert "MIT" in stats["licenses"]

    def test_package_managers_list_contains_all_seen(self, scanner: SBOMScanner):
        deps = [
            {"moduleName": "a", "packageManager": "pypi", "licenseConcluded": "MIT"},
            {"moduleName": "b", "packageManager": "npm", "licenseConcluded": "MIT"},
            {"moduleName": "c", "packageManager": "maven", "licenseConcluded": "MIT"},
        ]
        stats = scanner._calculate_statistics(deps)
        assert set(stats["package_managers"]) == {"pypi", "npm", "maven"}
        assert stats["total_package_managers"] == 3


class TestDependenciesToFindings:
    def test_known_low_risk_license_is_low_severity(self, scanner: SBOMScanner):
        dep = {
            "moduleName": "requests",
            "versionInfo": "2.31.0",
            "packageManager": "pypi",
            "licenseConcluded": "MIT",
            "sha": "abc",
            "sourceLocation": "requirements.txt",
            "packageURL": _build_pypi_url("requests"),
        }
        findings = scanner._dependencies_to_findings([dep])

        assert len(findings) == 1
        assert findings[0].severity == "low"
        assert findings[0].match == "requests"
        assert findings[0].url == _build_pypi_url("requests")

    @pytest.mark.parametrize("license_val", ["-", None, "unknown"])
    def test_missing_or_empty_license_is_high_severity(
        self, scanner: SBOMScanner, license_val
    ):
        # Missing/empty license is treated the same as NOASSERTION in
        # LICENSE_POLICY_MAP.json - "High" risk, not a middling "Medium".
        dep = {
            "moduleName": "orphan-lib",
            "versionInfo": "1.0.0",
            "packageManager": "pypi",
            "licenseConcluded": license_val,
            "sha": "Unknown",
            "sourceLocation": "requirements.txt",
            "packageURL": _build_pypi_url("orphan-lib"),
        }
        findings = scanner._dependencies_to_findings([dep])
        assert findings[0].severity == "high"

    def test_copyleft_license_is_high_severity(self, scanner: SBOMScanner):
        dep = {
            "moduleName": "gpl-lib",
            "versionInfo": "1.0.0",
            "packageManager": "pypi",
            "licenseConcluded": "GPL-3.0",
            "sha": "abc",
            "sourceLocation": "requirements.txt",
            "packageURL": _build_pypi_url("gpl-lib"),
        }
        findings = scanner._dependencies_to_findings([dep])
        assert findings[0].severity == "high"

    def test_weak_copyleft_license_is_medium_severity(self, scanner: SBOMScanner):
        dep = {
            "moduleName": "lgpl-lib",
            "versionInfo": "1.0.0",
            "packageManager": "pypi",
            "licenseConcluded": "LGPL-2.1",
            "sha": "abc",
            "sourceLocation": "requirements.txt",
            "packageURL": _build_pypi_url("lgpl-lib"),
        }
        findings = scanner._dependencies_to_findings([dep])
        assert findings[0].severity == "medium"

    def test_unmapped_but_present_license_is_high_severity(self, scanner: SBOMScanner):
        # A real, non-empty SPDX id with no entry in LICENSE_POLICY_MAP.json
        # must be treated the same as NOASSERTION ("High"), not silently "Low" -
        # matches the frontend's getLicenseInfo() NOASSERTION fallback.
        dep = {
            "moduleName": "obscure-lib",
            "versionInfo": "1.0.0",
            "packageManager": "pypi",
            "licenseConcluded": "Some-Obscure-License-9.9",
            "sha": "abc",
            "sourceLocation": "requirements.txt",
            "packageURL": _build_pypi_url("obscure-lib"),
        }
        findings = scanner._dependencies_to_findings([dep])
        assert findings[0].severity == "high"

    def test_compound_and_license_uses_highest_risk_member(self, scanner: SBOMScanner):
        # "MIT AND GPL-3.0" - conjunctive, so the combined obligation is the
        # worst case (High from GPL-3.0), not the best case (Low from MIT).
        dep = {
            "moduleName": "dual-licensed-lib",
            "versionInfo": "1.0.0",
            "packageManager": "pypi",
            "licenseConcluded": "MIT AND GPL-3.0",
            "sha": "abc",
            "sourceLocation": "requirements.txt",
            "packageURL": _build_pypi_url("dual-licensed-lib"),
        }
        findings = scanner._dependencies_to_findings([dep])
        assert findings[0].severity == "high"

    def test_variable_risk_license_is_medium_severity(self, scanner: SBOMScanner):
        # "Variable" (custom/negotiated enterprise licenses) has no clean
        # ScanSeverity equivalent, so it maps to MEDIUM rather than HIGH/LOW.
        dep = {
            "moduleName": "enterprise-lib",
            "versionInfo": "1.0.0",
            "packageManager": "pypi",
            "licenseConcluded": "LicenseRef-Enterprise",
            "sha": "abc",
            "sourceLocation": "requirements.txt",
            "packageURL": _build_pypi_url("enterprise-lib"),
        }
        findings = scanner._dependencies_to_findings([dep])
        assert findings[0].severity == "medium"

    def test_dash_license_shows_dash_in_description(self, scanner: SBOMScanner):
        dep = {
            "moduleName": "orphan-lib",
            "versionInfo": "1.0.0",
            "packageManager": "pypi",
            "licenseConcluded": "-",
            "sha": "Unknown",
            "sourceLocation": "sbom.json",
            "packageURL": _build_pypi_url("orphan-lib"),
        }
        finding = scanner._dependencies_to_findings([dep])[0]
        assert "License: -" in finding.description

    def test_finding_fields_mapped_correctly(self, scanner: SBOMScanner):
        dep = {
            "moduleName": "guava",
            "versionInfo": "33.0.0",
            "packageManager": "maven",
            "licenseConcluded": "Apache-2.0",
            "sha": "cafebabe",
            "sourceLocation": "pom.xml",
            "packageURL": _build_maven_url("com.google.guava:guava"),
        }
        finding = scanner._dependencies_to_findings([dep])[0]
        assert finding.code == "cafebabe"
        assert finding.file == "pom.xml"
        assert finding.match == "guava"
        assert finding.url == _build_maven_url("com.google.guava:guava")
        assert "maven" in finding.policy

    def test_description_contains_name_version_manager(self, scanner: SBOMScanner):
        dep = {
            "moduleName": "lodash",
            "versionInfo": "4.17.21",
            "packageManager": "npm",
            "licenseConcluded": "MIT",
            "sha": "abc",
            "sourceLocation": "package.json",
            "packageURL": _build_npm_url("lodash"),
        }
        finding = scanner._dependencies_to_findings([dep])[0]
        assert "lodash" in finding.description
        assert "4.17.21" in finding.description
        assert "npm" in finding.description


class TestReadSbomArtifactFormattedOutput:
    def test_spdx_json_deps_enriched_with_stacks(
        self, scanner: SBOMScanner, tmp_path: Path
    ):
        spdx_doc = {
            "spdxVersion": "SPDX-2.3",
            "packages": [
                {
                    "name": "flask",
                    "versionInfo": "3.0.0",
                    "licenseConcluded": "BSD-3-Clause",
                    "externalRefs": [
                        {
                            "referenceType": "purl",
                            "referenceLocator": "pkg:pypi/flask@3.0.0",
                        }
                    ],
                }
            ],
        }
        bom_path = tmp_path / "sbom-spdx.json"
        bom_path.write_text(json.dumps(spdx_doc), encoding="utf-8")

        with patch(
            "scanner_core.microservices.sbom_scanner.get_package_by_name",
            return_value=None,
        ):
            deps = scanner._read_sbom_artifact_dependencies([str(bom_path)])

        formatted = scanner._build_sbom_formatted_output(deps)
        stats = scanner._calculate_statistics(deps)
        findings = scanner._dependencies_to_findings(deps)

        assert len(formatted) == 1
        assert formatted[0]["name"] == "flask"
        assert formatted[0]["purl"] == "pkg:pypi/flask@3.0.0"
        assert formatted[0]["stacks"]["spdx"]["id"].startswith("SPDXRef-Package-0-")
        assert stats["total_packages"] == 1
        # Mongo miss overwrites SPDX licenseConcluded with "-"
        assert deps[0]["licenseConcluded"] == "-"
        assert formatted[0]["license"] == "-"
        assert stats["legal_review_required"] is True
        assert findings[0].severity == "high"

    def test_cyclonedx_without_licenses_produces_high_finding(
        self, scanner: SBOMScanner, tmp_path: Path
    ):
        bom = {
            "bomFormat": "CycloneDX",
            "components": [
                {
                    "name": "orphan-lib",
                    "version": "1.0.0",
                    "purl": "pkg:generic/orphan-lib@1.0.0",
                }
            ],
        }
        bom_path = tmp_path / "cyclonedx-sbom.json"
        bom_path.write_text(json.dumps(bom), encoding="utf-8")

        with patch(
            "scanner_core.microservices.sbom_scanner.get_package_by_name",
            return_value=None,
        ):
            deps = scanner._read_sbom_artifact_dependencies([str(bom_path)])

        formatted = scanner._build_sbom_formatted_output(deps)
        stats = scanner._calculate_statistics(deps)
        findings = scanner._dependencies_to_findings(deps)

        assert len(deps) == 1
        assert deps[0]["licenseConcluded"] == "-"
        assert formatted[0]["license"] == "-"
        assert stats["unknown_licenses_count"] == 1
        assert stats["legal_review_required"] is True
        assert findings[0].severity == "high"

    def test_cyclonedx_with_license_produces_low_finding(
        self, scanner: SBOMScanner, tmp_path: Path
    ):
        bom = {
            "bomFormat": "CycloneDX",
            "components": [
                {
                    "name": "lodash",
                    "version": "4.17.21",
                    "purl": "pkg:npm/lodash@4.17.21",
                    "licenses": [{"license": {"id": "MIT"}}],
                }
            ],
        }
        bom_path = tmp_path / "cyclonedx-sbom.json"
        bom_path.write_text(json.dumps(bom), encoding="utf-8")

        # _get_license is called for known managers (npm) and overwrites the
        # component license; mock it to return MIT so enrichment preserves the license.
        with patch.object(
            SBOMScanner,
            "_get_license",
            return_value=("MIT", _build_npm_url("lodash"), "abc123", None),
        ):
            deps = scanner._read_sbom_artifact_dependencies([str(bom_path)])

        findings = scanner._dependencies_to_findings(deps)
        assert findings[0].severity == "low"
        assert deps[0]["licenseConcluded"] == "MIT"

    def test_spdx_multiple_packages_all_parsed(
        self, scanner: SBOMScanner, tmp_path: Path
    ):
        spdx_doc = {
            "spdxVersion": "SPDX-2.3",
            "packages": [
                {
                    "name": "flask",
                    "versionInfo": "3.0.0",
                    "licenseConcluded": "BSD-3-Clause",
                    "externalRefs": [
                        {"referenceType": "purl", "referenceLocator": "pkg:pypi/flask@3.0.0"}
                    ],
                },
                {
                    "name": "werkzeug",
                    "versionInfo": "3.0.1",
                    "licenseConcluded": "BSD-3-Clause",
                    "externalRefs": [
                        {"referenceType": "purl", "referenceLocator": "pkg:pypi/werkzeug@3.0.1"}
                    ],
                },
                {
                    "name": "click",
                    "versionInfo": "8.1.7",
                    "licenseConcluded": "BSD-3-Clause",
                    "externalRefs": [
                        {"referenceType": "purl", "referenceLocator": "pkg:pypi/click@8.1.7"}
                    ],
                },
            ],
        }
        bom_path = tmp_path / "sbom-spdx.json"
        bom_path.write_text(json.dumps(spdx_doc), encoding="utf-8")

        with patch(
            "scanner_core.microservices.sbom_scanner.get_package_by_name",
            return_value=None,
        ):
            deps = scanner._read_sbom_artifact_dependencies([str(bom_path)])

        formatted = scanner._build_sbom_formatted_output(deps)
        stats = scanner._calculate_statistics(deps)

        assert len(deps) == 3
        assert len(formatted) == 3
        assert stats["total_packages"] == 3
        assert {e["name"] for e in formatted} == {"flask", "werkzeug", "click"}

    def test_invalid_json_artifact_returns_empty(
        self, scanner: SBOMScanner, tmp_path: Path
    ):
        bad = tmp_path / "bad-sbom.json"
        bad.write_text("{not valid json{{", encoding="utf-8")
        deps = scanner._read_sbom_artifact_dependencies([str(bad)])
        assert deps == []

    def test_spdx_package_without_purl_has_unknown_manager(
        self, scanner: SBOMScanner, tmp_path: Path
    ):
        spdx_doc = {
            "spdxVersion": "SPDX-2.3",
            "packages": [{"name": "internal-lib", "versionInfo": "0.1.0"}],
        }
        bom_path = tmp_path / "sbom-spdx.json"
        bom_path.write_text(json.dumps(spdx_doc), encoding="utf-8")

        deps = scanner._read_sbom_artifact_dependencies([str(bom_path)])
        assert deps[0]["packageManager"] == "unknown"
        assert deps[0]["packageURL"] == "Unknown"


    def test_cyclonedx_component_type_preserved_in_stacks(
        self, scanner: SBOMScanner, tmp_path: Path
    ):
        bom = {
            "bomFormat": "CycloneDX",
            "components": [
                {
                    "type": "framework",
                    "name": "django",
                    "version": "5.0.0",
                    "purl": "pkg:pypi/django@5.0.0",
                    "licenses": [{"license": {"id": "BSD-3-Clause"}}],
                }
            ],
        }
        bom_path = tmp_path / "cyclonedx-framework.json"
        bom_path.write_text(json.dumps(bom), encoding="utf-8")

        with patch.object(
            SBOMScanner,
            "_get_license",
            return_value=("BSD-3-Clause", _build_pypi_url("django"), "abc123", None),
        ):
            deps = scanner._read_sbom_artifact_dependencies([str(bom_path)])

        formatted = scanner._build_sbom_formatted_output(deps)
        assert deps[0]["componentType"] == "framework"
        assert formatted[0]["stacks"]["cyclonedx"]["type"] == "framework"

    def test_lockfile_dependency_defaults_to_library_type(self, scanner: SBOMScanner):
        dep = {
            "moduleName": "requests",
            "versionInfo": "2.31.0",
            "packageManager": "pypi",
            "licenseConcluded": "MIT",
            "sha": "abc123",
            "sourceLocation": "requirements.txt",
            "packageURL": _build_pypi_url("requests"),
        }
        entry = scanner._build_sbom_formatted_output([dep])[0]
        assert entry["stacks"]["cyclonedx"]["type"] == "library"


class TestIsEmptyLicense:
    @pytest.mark.parametrize(
        "value",
        ["-", "unknown", "NOASSERTION", "none", "", None],
    )
    def test_empty_values_are_detected(self, value):
        assert SBOMScanner._is_empty_license(value) is True

    @pytest.mark.parametrize(
        "value",
        ["MIT", "Apache-2.0", "BSD-3-Clause"],
    )
    def test_valid_spdx_licenses_are_not_empty(self, value):
        assert SBOMScanner._is_empty_license(value) is False


class TestPackageManagerFromPurl:
    @pytest.mark.parametrize(
        "purl,expected",
        [
            ("pkg:pypi/requests@2.31.0", "pypi"),
            ("pkg:npm/lodash@4.17.21", "npm"),
            ("pkg:golang/github.com/gin-gonic/gin@1.9.0", "go"),
            ("pkg:maven/org.junit:junit@4.13", "maven"),
            ("pkg:gradle/com.example:demo@1.0", "gradle"),
        ],
    )
    def test_known_ecosystems(self, purl: str, expected: str):
        assert SBOMScanner._package_manager_from_purl(purl) == expected

    def test_none_returns_unknown(self):
        assert SBOMScanner._package_manager_from_purl(None) == "unknown"

    def test_empty_string_returns_unknown(self):
        assert SBOMScanner._package_manager_from_purl("") == "unknown"

    def test_missing_pkg_prefix_returns_unknown(self):
        assert SBOMScanner._package_manager_from_purl("pypi/requests@2.31.0") == "unknown"


class TestBuildSpdxDocument:
    def test_spdx_document_structure(self, scanner: SBOMScanner):
        enriched = scanner._build_sbom_formatted_output([
            {
                "moduleName": "requests",
                "versionInfo": "2.31.0",
                "packageManager": "pypi",
                "licenseConcluded": "MIT",
                "sha": "abc123",
                "sourceLocation": "requirements.txt",
                "packageURL": _build_pypi_url("requests"),
            }
        ])
        doc = scanner._build_spdx_document(enriched, "scan-001")

        assert doc["spdxVersion"] == "SPDX-2.3"
        assert doc["dataLicense"] == "CC0-1.0"
        assert doc["SPDXID"] == "SPDXRef-DOCUMENT"
        assert doc["name"] == "sbom-scan-001"
        assert "scan-001" in doc["documentNamespace"]
        assert len(doc["packages"]) == 1
        pkg = doc["packages"][0]
        assert pkg["name"] == "requests"
        assert pkg["versionInfo"] == "2.31.0"
        assert pkg["licenseConcluded"] == "MIT"
        assert pkg["filesAnalyzed"] is False
        assert pkg["externalRefs"][0]["referenceLocator"] == "pkg:pypi/requests@2.31.0"

    def test_missing_license_uses_noassertion(self, scanner: SBOMScanner):
        enriched = scanner._build_sbom_formatted_output([
            {
                "moduleName": "orphan",
                "versionInfo": "1.0.0",
                "packageManager": "pypi",
                "licenseConcluded": "-",
                "sha": "Unknown",
                "sourceLocation": "requirements.txt",
                "packageURL": _build_pypi_url("orphan"),
            }
        ])
        doc = scanner._build_spdx_document(enriched, "scan-002")
        assert doc["packages"][0]["licenseConcluded"] == "NOASSERTION"

    def test_package_without_version_omits_version_info(self, scanner: SBOMScanner):
        enriched = scanner._build_sbom_formatted_output([
            {
                "moduleName": "nover",
                "versionInfo": None,
                "packageManager": "pypi",
                "licenseConcluded": "MIT",
                "sha": "Unknown",
                "sourceLocation": "requirements.txt",
                "packageURL": _build_pypi_url("nover"),
            }
        ])
        doc = scanner._build_spdx_document(enriched, "scan-003")
        assert "versionInfo" not in doc["packages"][0]


class TestBuildCycloneDxDocument:
    def test_cyclonedx_document_structure(self, scanner: SBOMScanner):
        enriched = scanner._build_sbom_formatted_output([
            {
                "moduleName": "lodash",
                "versionInfo": "4.17.21",
                "packageManager": "npm",
                "licenseConcluded": "MIT",
                "sha": "abc",
                "sourceLocation": "package.json",
                "packageURL": _build_npm_url("lodash"),
            }
        ])
        doc = scanner._build_cyclonedx_document(enriched, "scan-001")

        assert doc["bomFormat"] == "CycloneDX"
        assert doc["specVersion"] == "1.5"
        assert doc["version"] == 1
        assert doc["serialNumber"] == "urn:uuid:scan-001"
        assert len(doc["components"]) == 1
        comp = doc["components"][0]
        assert comp["name"] == "lodash"
        assert comp["version"] == "4.17.21"
        assert comp["purl"] == "pkg:npm/lodash@4.17.21"
        assert comp["licenses"] == [{"license": {"id": "MIT"}}]
        assert comp["type"] == "library"

    def test_unknown_license_omits_licenses_field(self, scanner: SBOMScanner):
        enriched = scanner._build_sbom_formatted_output([
            {
                "moduleName": "orphan",
                "versionInfo": "1.0.0",
                "packageManager": "pypi",
                "licenseConcluded": "-",
                "sha": "Unknown",
                "sourceLocation": "requirements.txt",
                "packageURL": _build_pypi_url("orphan"),
            }
        ])
        doc = scanner._build_cyclonedx_document(enriched, "scan-002")
        assert "licenses" not in doc["components"][0]

    def test_framework_type_preserved(self, scanner: SBOMScanner):
        from unittest.mock import patch
        bom = {
            "bomFormat": "CycloneDX",
            "components": [{"type": "framework", "name": "django", "version": "5.0.0",
                            "purl": "pkg:pypi/django@5.0.0"}],
        }
        import json as _json
        import tempfile, os as _os
        with tempfile.TemporaryDirectory() as tmp:
            p = _os.path.join(tmp, "bom.json")
            with open(p, "w") as f:
                _json.dump(bom, f)
            with patch.object(SBOMScanner, "_get_license",
                              return_value=("BSD-3-Clause", _build_pypi_url("django"), "x", None)):
                deps = scanner._read_sbom_artifact_dependencies([p])
        enriched = scanner._build_sbom_formatted_output(deps)
        doc = scanner._build_cyclonedx_document(enriched, "scan-003")
        assert doc["components"][0]["type"] == "framework"


class TestWriteSbomFiles:
    def test_writes_spdx_and_cyclonedx_files(self, scanner: SBOMScanner, tmp_path):
        enriched = scanner._build_sbom_formatted_output([
            {
                "moduleName": "requests",
                "versionInfo": "2.31.0",
                "packageManager": "pypi",
                "licenseConcluded": "MIT",
                "sha": "abc123",
                "sourceLocation": "requirements.txt",
                "packageURL": _build_pypi_url("requests"),
            }
        ])
        scanner._write_sbom_files(enriched, "scan-xyz", str(tmp_path))

        spdx_path = tmp_path / "spdx.json"
        cdx_path = tmp_path / "cyclonedx.json"
        assert spdx_path.exists()
        assert cdx_path.exists()

        spdx_doc = json.loads(spdx_path.read_text())
        assert spdx_doc["spdxVersion"] == "SPDX-2.3"
        assert len(spdx_doc["packages"]) == 1

        cdx_doc = json.loads(cdx_path.read_text())
        assert cdx_doc["bomFormat"] == "CycloneDX"
        assert len(cdx_doc["components"]) == 1

    def test_creates_output_dir_if_missing(self, scanner: SBOMScanner, tmp_path):
        target = tmp_path / "nested" / "output"
        enriched = scanner._build_sbom_formatted_output([
            {
                "moduleName": "flask",
                "versionInfo": "3.0.0",
                "packageManager": "pypi",
                "licenseConcluded": "BSD-3-Clause",
                "sha": "abc",
                "sourceLocation": "requirements.txt",
                "packageURL": _build_pypi_url("flask"),
            }
        ])
        scanner._write_sbom_files(enriched, "scan-abc", str(target))
        assert (target / "spdx.json").exists()
        assert (target / "cyclonedx.json").exists()


class TestSbomProgressLogging:
    """_log_sbom_progress must log only twice per scan - once at ~50% and once
    at 100% - never once per package, regardless of how many packages there are."""

    def test_logs_exactly_twice_for_many_packages(self, scanner: SBOMScanner, caplog):
        scanner._sbom_progress_total = 10
        caplog.set_level("INFO", logger="scanner")

        for _ in range(10):
            scanner._sbom_progress_current += 1
            scanner._log_sbom_progress()

        progress_records = [r for r in caplog.records if "[SBOM] Scanned" in r.message]
        assert len(progress_records) == 2
        assert "~50%" in progress_records[0].message
        assert "100%, complete" in progress_records[1].message

    def test_does_not_log_again_once_both_milestones_hit(self, scanner: SBOMScanner, caplog):
        scanner._sbom_progress_total = 2
        caplog.set_level("INFO", logger="scanner")

        scanner._sbom_progress_current = 2
        scanner._log_sbom_progress()
        scanner._log_sbom_progress()  # called again - must not double-log
        scanner._log_sbom_progress()

        progress_records = [r for r in caplog.records if "[SBOM] Scanned" in r.message]
        assert len(progress_records) == 2

    def test_no_log_when_total_is_zero(self, scanner: SBOMScanner, caplog):
        scanner._sbom_progress_total = 0
        caplog.set_level("INFO", logger="scanner")

        scanner._log_sbom_progress()

        progress_records = [r for r in caplog.records if "[SBOM] Scanned" in r.message]
        assert len(progress_records) == 0

    def test_single_package_scan_still_logs_both_milestones(
        self, scanner: SBOMScanner, caplog
    ):
        # halfway = (1 + 1) // 2 == 1, so the first (only) package satisfies
        # both the half and complete thresholds in the same call.
        scanner._sbom_progress_total = 1
        caplog.set_level("INFO", logger="scanner")

        scanner._sbom_progress_current = 1
        scanner._log_sbom_progress()

        progress_records = [r for r in caplog.records if "[SBOM] Scanned" in r.message]
        assert len(progress_records) == 2
