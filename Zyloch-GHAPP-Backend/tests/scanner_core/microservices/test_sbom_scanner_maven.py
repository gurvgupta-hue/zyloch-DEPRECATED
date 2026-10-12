"""Pytests for Maven package version handling in SBOMScanner."""
from __future__ import annotations

import textwrap
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import patch

import pytest

from scanner_core.microservices.sbom_scanner import SBOMScanner

POM_NS = "http://maven.apache.org/POM/4.0.0"


def _pom_body(inner: str, *, version: str = "1.0.0") -> str:
    return textwrap.dedent(
        f"""\
        <?xml version="1.0" encoding="UTF-8"?>
        <project xmlns="{POM_NS}">
          <modelVersion>4.0.0</modelVersion>
          <groupId>com.example</groupId>
          <artifactId>demo</artifactId>
          <version>{version}</version>
        {inner}
        </project>
        """
    )


def _write_pom(tmp_path: Path, filename: str, content: str) -> Path:
    pom_path = tmp_path / filename
    pom_path.write_text(content, encoding="utf-8")
    return pom_path


@pytest.fixture
def scanner() -> SBOMScanner:
    return SBOMScanner()


@pytest.fixture
def license_stub():
    """Avoid Mongo/license lookups during dependency parsing tests."""

    def _fake_license(
        name: str, manager: str, version: Optional[str] = None
    ) -> tuple[str, str, str, Optional[str]]:
        return ("Apache-2.0", f"pkg:maven/{name}@{version or ''}", "", None)

    with patch.object(SBOMScanner, "_get_license", side_effect=_fake_license):
        yield


class TestGetMavenVersionFromMongo:
    @pytest.mark.parametrize(
        "mongo_payload,expected",
        [
            ({"object": {"latestVersion": "2.14.0"}}, "2.14.0"),
            ({"object": {"latest_version": "3.1.2"}}, "3.1.2"),
            ({"object": {"version": "1.0.0"}}, "1.0.0"),
            ({"object": {"v": "4.5.6"}}, "4.5.6"),
            (
                {"object": {"object": {"latestVersion": "9.0.0"}}},
                "9.0.0",
            ),
            (
                {"object": {"versions": {"1.0": {}, "2.0": {}, "3.0": {}}}},
                "3.0",
            ),
            (
                {"object": {"releases": {"alpha": {}, "beta": {}, "ga": {}}}},
                "ga",
            ),
        ],
    )
    def test_extracts_version_from_document_shapes(
        self, scanner: SBOMScanner, mongo_payload: Dict[str, Any], expected: str
    ):
        with patch(
            "scanner_core.microservices.sbom_scanner.get_package_by_name",
            return_value=mongo_payload,
        ):
            assert scanner._get_maven_version_from_mongo("org.junit:junit") == expected

    def test_returns_none_when_package_missing(self, scanner: SBOMScanner):
        with patch(
            "scanner_core.microservices.sbom_scanner.get_package_by_name",
            return_value=None,
        ):
            assert scanner._get_maven_version_from_mongo("missing:artifact") is None

    def test_returns_none_when_object_has_no_version_fields(self, scanner: SBOMScanner):
        with patch(
            "scanner_core.microservices.sbom_scanner.get_package_by_name",
            return_value={"object": {"name": "foo"}},
        ):
            assert scanner._get_maven_version_from_mongo("foo:bar") is None

    def test_ignores_whitespace_only_version(self, scanner: SBOMScanner):
        with patch(
            "scanner_core.microservices.sbom_scanner.get_package_by_name",
            return_value={"object": {"latestVersion": "   "}},
        ):
            assert scanner._get_maven_version_from_mongo("foo:bar") is None

    def test_handles_direct_dict_without_wrapper(self, scanner: SBOMScanner):
        with patch(
            "scanner_core.microservices.sbom_scanner.get_package_by_name",
            return_value={"version": "7.8.9"},
        ):
            assert scanner._get_maven_version_from_mongo("com.google:guava") == "7.8.9"


class TestReadJavaMavenDependencies:
    def test_reads_explicit_dependency_version(
        self, scanner: SBOMScanner, tmp_path: Path, license_stub
    ):
        pom = _write_pom(
            tmp_path,
            "pom.xml",
            _pom_body(
                """
          <dependencies>
            <dependency>
              <groupId>org.apache.commons</groupId>
              <artifactId>commons-lang3</artifactId>
              <version>3.14.0</version>
            </dependency>
          </dependencies>
        """
            ),
        )
        deps = scanner._read_java_maven_dependencies(
            {"java_maven": [str(pom)]}, str(tmp_path)
        )

        assert len(deps) == 1
        assert deps[0]["moduleName"] == "org.apache.commons:commons-lang3"
        assert deps[0]["versionInfo"] == "3.14.0"
        assert deps[0]["packageManager"] == "maven"
        assert deps[0]["sourceLocation"] == str(pom)

    def test_resolves_property_placeholder_in_version(
        self, scanner: SBOMScanner, tmp_path: Path, license_stub
    ):
        pom = _write_pom(
            tmp_path,
            "pom.xml",
            _pom_body(
                """
          <properties>
            <spring.version>6.1.5</spring.version>
          </properties>
          <dependencies>
            <dependency>
              <groupId>org.springframework</groupId>
              <artifactId>spring-core</artifactId>
              <version>${spring.version}</version>
            </dependency>
          </dependencies>
        """
            ),
        )
        deps = scanner._read_java_maven_dependencies(
            {"java_maven": [str(pom)]}, str(tmp_path)
        )

        assert deps[0]["versionInfo"] == "6.1.5"

    def test_resolves_chained_property_placeholders(
        self, scanner: SBOMScanner, tmp_path: Path, license_stub
    ):
        pom = _write_pom(
            tmp_path,
            "pom.xml",
            _pom_body(
                """
          <properties>
            <jackson.patch>2</jackson.patch>
            <jackson.minor>17</jackson.minor>
            <jackson.version>${jackson.minor}.${jackson.patch}.1</jackson.version>
          </properties>
          <dependencies>
            <dependency>
              <groupId>com.fasterxml.jackson.core</groupId>
              <artifactId>jackson-databind</artifactId>
              <version>${jackson.version}</version>
            </dependency>
          </dependencies>
        """
            ),
        )
        deps = scanner._read_java_maven_dependencies(
            {"java_maven": [str(pom)]}, str(tmp_path)
        )

        assert deps[0]["versionInfo"] == "17.2.1"

    def test_uses_project_version_property(
        self, scanner: SBOMScanner, tmp_path: Path, license_stub
    ):
        pom = _write_pom(
            tmp_path,
            "pom.xml",
            _pom_body(
                """
          <dependencies>
            <dependency>
              <groupId>com.example</groupId>
              <artifactId>demo-lib</artifactId>
              <version>${project.version}</version>
            </dependency>
          </dependencies>
        """,
                version="2.3.4",
            ),
        )
        deps = scanner._read_java_maven_dependencies(
            {"java_maven": [str(pom)]}, str(tmp_path)
        )

        assert deps[0]["versionInfo"] == "2.3.4"

    def test_falls_back_to_mongo_when_version_element_missing(
        self, scanner: SBOMScanner, tmp_path: Path, license_stub
    ):
        pom = _write_pom(
            tmp_path,
            "pom.xml",
            _pom_body(
                """
          <dependencies>
            <dependency>
              <groupId>org.slf4j</groupId>
              <artifactId>slf4j-api</artifactId>
            </dependency>
          </dependencies>
        """
            ),
        )
        with patch.object(
            SBOMScanner,
            "_get_maven_version_from_mongo",
            return_value="2.0.12",
        ) as mongo_mock:
            deps = scanner._read_java_maven_dependencies(
                {"java_maven": [str(pom)]}, str(tmp_path)
            )

        mongo_mock.assert_called_once_with("org.slf4j:slf4j-api")
        assert deps[0]["versionInfo"] == "2.0.12"

    def test_falls_back_to_mongo_when_placeholder_unresolved(
        self, scanner: SBOMScanner, tmp_path: Path, license_stub
    ):
        pom = _write_pom(
            tmp_path,
            "pom.xml",
            _pom_body(
                """
          <dependencies>
            <dependency>
              <groupId>io.netty</groupId>
              <artifactId>netty-all</artifactId>
              <version>${undefined.version}</version>
            </dependency>
          </dependencies>
        """
            ),
        )
        with patch.object(
            SBOMScanner,
            "_get_maven_version_from_mongo",
            return_value="4.1.108.Final",
        ):
            deps = scanner._read_java_maven_dependencies(
                {"java_maven": [str(pom)]}, str(tmp_path)
            )

        assert deps[0]["versionInfo"] == "4.1.108.Final"

    def test_version_none_when_pom_and_mongo_have_no_version(
        self, scanner: SBOMScanner, tmp_path: Path, license_stub
    ):
        pom = _write_pom(
            tmp_path,
            "pom.xml",
            _pom_body(
                """
          <dependencies>
            <dependency>
              <groupId>unknown</groupId>
              <artifactId>missing</artifactId>
            </dependency>
          </dependencies>
        """
            ),
        )
        with patch.object(
            SBOMScanner, "_get_maven_version_from_mongo", return_value=None
        ):
            deps = scanner._read_java_maven_dependencies(
                {"java_maven": [str(pom)]}, str(tmp_path)
            )

        assert deps[0]["versionInfo"] is None

    def test_skips_dependency_without_group_or_artifact(
        self, scanner: SBOMScanner, tmp_path: Path, license_stub
    ):
        pom = _write_pom(
            tmp_path,
            "pom.xml",
            _pom_body(
                """
          <dependencies>
            <dependency>
              <artifactId>orphan</artifactId>
              <version>1.0</version>
            </dependency>
            <dependency>
              <groupId>valid</groupId>
              <artifactId>dep</artifactId>
              <version>2.0</version>
            </dependency>
          </dependencies>
        """
            ),
        )
        deps = scanner._read_java_maven_dependencies(
            {"java_maven": [str(pom)]}, str(tmp_path)
        )

        assert len(deps) == 1
        assert deps[0]["moduleName"] == "valid:dep"

    def test_parses_multiple_dependencies(
        self, scanner: SBOMScanner, tmp_path: Path, license_stub
    ):
        pom = _write_pom(
            tmp_path,
            "pom.xml",
            _pom_body(
                """
          <dependencies>
            <dependency>
              <groupId>a</groupId>
              <artifactId>one</artifactId>
              <version>1.0</version>
            </dependency>
            <dependency>
              <groupId>b</groupId>
              <artifactId>two</artifactId>
              <version>2.0</version>
            </dependency>
          </dependencies>
        """
            ),
        )
        deps = scanner._read_java_maven_dependencies(
            {"java_maven": [str(pom)]}, str(tmp_path)
        )

        versions = {d["moduleName"]: d["versionInfo"] for d in deps}
        assert versions == {"a:one": "1.0", "b:two": "2.0"}

    def test_normalizes_unknown_license_to_dash(
        self, scanner: SBOMScanner, tmp_path: Path
    ):
        pom = _write_pom(
            tmp_path,
            "pom.xml",
            _pom_body(
                """
          <dependencies>
            <dependency>
              <groupId>junit</groupId>
              <artifactId>junit</artifactId>
              <version>4.13.2</version>
            </dependency>
          </dependencies>
        """
            ),
        )

        def _unknown_license(name, manager, version=None):
            return ("unknown", "", "", None)

        with patch.object(SBOMScanner, "_get_license", side_effect=_unknown_license):
            deps = scanner._read_java_maven_dependencies(
                {"java_maven": [str(pom)]}, str(tmp_path)
            )

        assert deps[0]["licenseConcluded"] == "-"

    def test_returns_empty_list_for_invalid_pom(
        self, scanner: SBOMScanner, tmp_path: Path, license_stub
    ):
        bad_pom = tmp_path / "pom.xml"
        bad_pom.write_text("<not-valid-xml", encoding="utf-8")

        deps = scanner._read_java_maven_dependencies(
            {"java_maven": [str(bad_pom)]}, str(tmp_path)
        )

        assert deps == []

    def test_returns_empty_when_no_java_maven_files(
        self, scanner: SBOMScanner, tmp_path: Path, license_stub
    ):
        deps = scanner._read_java_maven_dependencies({}, str(tmp_path))
        assert deps == []
