"""SBOM tests: packageURL when Mongo is empty; license uses '-' not 'unknown'."""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from scanner_core.microservices.sbom_scanner import SBOMScanner, _build_pypi_url


@pytest.fixture
def scanner() -> SBOMScanner:
    return SBOMScanner()


class TestGetLicenseMongoMiss:
    def test_pypi_returns_dash_license_and_registry_url_when_mongo_missing(
        self, scanner: SBOMScanner
    ):
        with patch(
            "scanner_core.microservices.sbom_scanner.get_package_by_name",
            return_value=None,
        ):
            license_val, package_url, sha, mongo_version = scanner._get_license(
                "requests", "pypi", "2.31.0"
            )

        assert license_val == "-"
        assert package_url == _build_pypi_url("requests", "2.31.0")
        assert sha == "Unknown"
        assert mongo_version is None

    def test_is_empty_license_treats_unknown_as_missing(self, scanner: SBOMScanner):
        assert scanner._is_empty_license("unknown") is True
        assert scanner._is_empty_license("Unknown") is True
        assert scanner._is_empty_license("-") is True


class TestGetLicensePackageUrlIsAlwaysVersioned:
    """PyPI/npm/Go/Maven's own Mongo-cached package_url is only ever the generic
    project page, never per-version - _get_license must always rebuild the
    official registry URL itself rather than trust that cached value verbatim."""

    def test_pypi_ignores_mongo_stored_package_url_and_adds_version(
        self, scanner: SBOMScanner
    ):
        mongo_doc = {
            "object": {
                "info": {
                    "license": "MIT",
                    "version": "2.31.0",
                    "package_url": "https://pypi.org/project/requests/",
                },
                "version": "2.31.0",
            }
        }
        with patch(
            "scanner_core.microservices.sbom_scanner.get_package_by_name",
            return_value=mongo_doc,
        ):
            _license_val, package_url, _sha, _mongo_version = scanner._get_license(
                "requests", "pypi", "2.31.0"
            )
        assert package_url == _build_pypi_url("requests", "2.31.0")

    def test_npm_ignores_mongo_stored_package_url_and_adds_version(
        self, scanner: SBOMScanner
    ):
        mongo_doc = {
            "object": {
                "license": "MIT",
                "package_url": "https://www.npmjs.com/package/lodash",
            }
        }
        with patch(
            "scanner_core.microservices.sbom_scanner.get_package_by_name",
            return_value=mongo_doc,
        ):
            _license_val, package_url, _sha, _mv = scanner._get_license(
                "lodash", "npm", "4.17.21"
            )
        from scanner_core.microservices.sbom_scanner import _build_npm_url
        assert package_url == _build_npm_url("lodash", "4.17.21")

    def test_maven_ignores_mongo_stored_package_url_and_adds_version(
        self, scanner: SBOMScanner
    ):
        mongo_doc = {
            "object": {
                "g": "com.google.guava",
                "a": "guava",
                "package_url": "https://mvnrepository.com/artifact/com.google.guava/guava",
            }
        }
        with patch(
            "scanner_core.microservices.sbom_scanner.get_package_by_name",
            return_value=mongo_doc,
        ):
            _license_val, package_url, _sha, _mv = scanner._get_license(
                "com.google.guava:guava", "maven", "33.0.0"
            )
        from scanner_core.microservices.sbom_scanner import _build_maven_url
        assert package_url == _build_maven_url("com.google.guava:guava", "33.0.0")


class TestReadSbomArtifactDependencies:
    def test_cyclonedx_purl_kept_and_license_dash_when_mongo_missing(
        self, scanner: SBOMScanner, tmp_path: Path
    ):
        purl = "pkg:pypi/requests@2.31.0"
        bom = {
            "bomFormat": "CycloneDX",
            "components": [
                {
                    "name": "requests",
                    "version": "2.31.0",
                    "purl": purl,
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

        assert len(deps) == 1
        dep = deps[0]
        assert dep["licenseConcluded"] == "-"
        assert dep["packageURL"] == _build_pypi_url("requests", "2.31.0")
        assert dep["packageURL"] != "Unknown"
        assert dep["packageURL"] != "unknown"

    def test_cyclonedx_without_licenses_defaults_to_dash_before_enrichment(
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
        bom_path = tmp_path / "sbom.json"
        bom_path.write_text(json.dumps(bom), encoding="utf-8")

        deps = scanner._read_sbom_artifact_dependencies([str(bom_path)])

        assert len(deps) == 1
        assert deps[0]["licenseConcluded"] == "-"
        assert deps[0]["packageURL"] == "pkg:generic/orphan-lib@1.0.0"
