from __future__ import annotations

import json
import textwrap
from pathlib import Path
from typing import Optional
from unittest.mock import patch

import pytest

from scanner_core.microservices.sbom_scanner import SBOMScanner


@pytest.fixture
def scanner() -> SBOMScanner:
    return SBOMScanner()


@pytest.fixture
def license_stub():
    """Avoid Mongo/license lookups during dependency parsing tests."""

    def _fake_license(name: str, manager: str, version: Optional[str] = None):
        return ("Apache-2.0", f"pkg:{manager}/{name}@{version or ''}", "sha-stub", None)

    with patch.object(SBOMScanner, "_get_license", side_effect=_fake_license):
        yield


def _write(tmp_path: Path, rel_path: str, content: str) -> Path:
    p = tmp_path / rel_path
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(textwrap.dedent(content), encoding="utf-8")
    return p


class TestFileTypesIncludeLockfiles:
    def test_python_file_types_include_lockfiles(self, scanner: SBOMScanner):
        assert "Pipfile.lock" in scanner.file_types["python"]
        assert "poetry.lock" in scanner.file_types["python"]

    def test_gradle_file_types_include_lockfile(self, scanner: SBOMScanner):
        assert "gradle.lockfile" in scanner.file_types["java_gradle"]

    def test_javascript_file_types_include_lockfile(self, scanner: SBOMScanner):
        assert "package-lock.json" in scanner.file_types["javascript"]


class TestReadPipfile:
    def test_reads_packages_and_dev_packages(self, scanner: SBOMScanner, tmp_path: Path, license_stub):
        pipfile = _write(
            tmp_path,
            "Pipfile",
            """\
            [packages]
            requests = "==2.31.0"
            flask = "*"

            [dev-packages]
            pytest = ">=7.0"
            """,
        )
        deps = scanner._read_pipfile(str(pipfile))
        by_name = {d["moduleName"]: d for d in deps}

        assert by_name["requests"]["versionInfo"] == "2.31.0"
        # "*" means "no pin" -> version becomes None -> _make_pypi_dependency
        # falls back to the "unspecified" sentinel (no mongo_version stubbed here).
        assert by_name["flask"]["versionInfo"] == "unspecified"
        assert by_name["pytest"]["versionInfo"] == "7.0"
        assert all(d["packageManager"] == "pypi" for d in deps)
        assert all(d["dependency_type"] == "direct" for d in deps)

    def test_reads_table_form_dependency_spec(self, scanner: SBOMScanner, tmp_path: Path, license_stub):
        pipfile = _write(
            tmp_path,
            "Pipfile",
            """\
            [packages]
            django = {version = "==5.0.1", extras = ["bcrypt"]}
            """,
        )
        deps = scanner._read_pipfile(str(pipfile))
        assert deps[0]["moduleName"] == "django"
        assert deps[0]["versionInfo"] == "5.0.1"


class TestReadPyprojectToml:
    def test_reads_pep621_project_dependencies(self, scanner: SBOMScanner, tmp_path: Path, license_stub):
        pyproject = _write(
            tmp_path,
            "pyproject.toml",
            """\
            [project]
            name = "demo"
            dependencies = [
                "requests==2.31.0",
                "flask>=3.0.0",
            ]
            """,
        )
        deps = scanner._read_pyproject_toml(str(pyproject))
        by_name = {d["moduleName"]: d["versionInfo"] for d in deps}
        assert by_name["requests"] == "2.31.0"
        assert by_name["flask"] == "3.0.0"

    def test_reads_poetry_dependencies_and_skips_python_pin(
        self, scanner: SBOMScanner, tmp_path: Path, license_stub
    ):
        pyproject = _write(
            tmp_path,
            "pyproject.toml",
            """\
            [tool.poetry.dependencies]
            python = "^3.11"
            requests = "^2.31.0"
            django = {version = "5.0.1"}
            """,
        )
        deps = scanner._read_pyproject_toml(str(pyproject))
        names = {d["moduleName"] for d in deps}

        assert "python" not in names
        by_name = {d["moduleName"]: d["versionInfo"] for d in deps}
        assert by_name["requests"] == "2.31.0"
        assert by_name["django"] == "5.0.1"

    def test_combines_pep621_and_poetry_sections(self, scanner: SBOMScanner, tmp_path: Path, license_stub):
        pyproject = _write(
            tmp_path,
            "pyproject.toml",
            """\
            [project]
            dependencies = ["requests==2.31.0"]

            [tool.poetry.dependencies]
            python = "^3.11"
            flask = "^3.0.0"
            """,
        )
        deps = scanner._read_pyproject_toml(str(pyproject))
        names = {d["moduleName"] for d in deps}
        assert names == {"requests", "flask"}


class TestReadPipfileLock:
    def test_all_sections_are_direct(self, scanner: SBOMScanner, tmp_path: Path, license_stub):
        """cvedb-fetcher has no Pipfile.lock parser - every pypi dependency it
        emits defaults to "direct" - so zyloch matches that instead of
        guessing at a transitive split cvedb-fetcher doesn't make."""
        lock = _write(
            tmp_path,
            "Pipfile.lock",
            json.dumps(
                {
                    "default": {
                        "requests": {"version": "==2.31.0"},
                        "urllib3": {"version": "==2.2.1"},
                    },
                    "develop": {
                        "pytest": {"version": "==8.0.0"},
                    },
                }
            ),
        )
        deps = scanner._read_pipfile_lock(str(lock))
        by_name = {d["moduleName"]: d for d in deps}

        assert by_name["requests"]["dependency_type"] == "direct"
        assert by_name["urllib3"]["dependency_type"] == "direct"
        assert by_name["pytest"]["dependency_type"] == "direct"
        assert by_name["requests"]["versionInfo"] == "2.31.0"


class TestReadPoetryLock:
    def test_all_packages_are_direct(self, scanner: SBOMScanner, tmp_path: Path, license_stub):
        """Same rationale as TestReadPipfileLock - cvedb-fetcher has no
        poetry.lock parser either."""
        lock = _write(
            tmp_path,
            "poetry.lock",
            """\
            [[package]]
            name = "requests"
            version = "2.31.0"

            [[package]]
            name = "urllib3"
            version = "2.2.1"
            """,
        )
        deps = scanner._read_poetry_lock(str(lock))
        by_name = {d["moduleName"]: d["dependency_type"] for d in deps}

        assert by_name["requests"] == "direct"
        assert by_name["urllib3"] == "direct"


class TestReadPythonDependenciesOrchestration:
    def test_prefers_lock_file_over_pipfile_when_both_present(
        self, scanner: SBOMScanner, tmp_path: Path, license_stub
    ):
        pipfile = _write(tmp_path, "Pipfile", '[packages]\nrequests = "==2.31.0"\n')
        lock = _write(
            tmp_path,
            "Pipfile.lock",
            json.dumps(
                {
                    "default": {"requests": {"version": "==2.31.0"}, "urllib3": {"version": "==2.2.1"}},
                    "develop": {},
                }
            ),
        )
        file_map = {"python": [str(pipfile), str(lock)]}

        deps = scanner._read_python_dependencies(file_map, str(tmp_path))
        names = {d["moduleName"] for d in deps}

        assert names == {"requests", "urllib3"}
        by_name = {d["moduleName"]: d["dependency_type"] for d in deps}
        assert by_name["urllib3"] == "direct"

    def test_falls_back_to_pipfile_only_when_no_lock_present(
        self, scanner: SBOMScanner, tmp_path: Path, license_stub
    ):
        pipfile = _write(tmp_path, "Pipfile", '[packages]\nrequests = "==2.31.0"\n')
        deps = scanner._read_python_dependencies({"python": [str(pipfile)]}, str(tmp_path))

        assert len(deps) == 1
        assert deps[0]["moduleName"] == "requests"
        assert deps[0]["dependency_type"] == "direct"

    def test_prefers_poetry_lock_over_pyproject_when_both_present(
        self, scanner: SBOMScanner, tmp_path: Path, license_stub
    ):
        pyproject = _write(
            tmp_path, "pyproject.toml", '[tool.poetry.dependencies]\nrequests = "^2.31.0"\n'
        )
        lock = _write(
            tmp_path,
            "poetry.lock",
            '[[package]]\nname = "requests"\nversion = "2.31.0"\n\n'
            '[[package]]\nname = "urllib3"\nversion = "2.2.1"\n',
        )
        deps = scanner._read_python_dependencies(
            {"python": [str(pyproject), str(lock)]}, str(tmp_path)
        )
        names = {d["moduleName"] for d in deps}
        assert names == {"requests", "urllib3"}

    def test_requirements_txt_still_read_independently_of_lock_logic(
        self, scanner: SBOMScanner, tmp_path: Path, license_stub
    ):
        reqs = _write(tmp_path, "requirements.txt", "requests==2.31.0\n")
        deps = scanner._read_python_dependencies({"python": [str(reqs)]}, str(tmp_path))
        assert deps[0]["moduleName"] == "requests"
        assert deps[0]["dependency_type"] == "direct"

    def test_multiple_project_dirs_are_handled_independently(
        self, scanner: SBOMScanner, tmp_path: Path, license_stub
    ):
        pipfile_a = _write(tmp_path, "svc-a/Pipfile", '[packages]\nrequests = "==2.31.0"\n')
        lock_a = _write(
            tmp_path,
            "svc-a/Pipfile.lock",
            json.dumps({"default": {"requests": {"version": "==2.31.0"}}, "develop": {}}),
        )
        reqs_b = _write(tmp_path, "svc-b/requirements.txt", "flask==3.0.0\n")

        deps = scanner._read_python_dependencies(
            {"python": [str(pipfile_a), str(lock_a), str(reqs_b)]}, str(tmp_path)
        )
        names = {d["moduleName"] for d in deps}
        assert names == {"requests", "flask"}


class TestReadBuildGradleFile:
    def test_matches_implementation_and_api_configurations(
        self, scanner: SBOMScanner, tmp_path: Path, license_stub
    ):
        build = _write(
            tmp_path,
            "build.gradle",
            """\
            dependencies {
                implementation 'com.google.guava:guava:33.0.0-jre'
                api "org.slf4j:slf4j-api:2.0.9"
            }
            """,
        )
        deps = scanner._read_build_gradle_file(str(build))
        names = {d["moduleName"] for d in deps}
        assert names == {"com.google.guava:guava", "org.slf4j:slf4j-api"}

    def test_matches_test_and_annotation_configurations(
        self, scanner: SBOMScanner, tmp_path: Path, license_stub
    ):
        # The old regex only recognized literal "implementation"/"api"; the
        # broadened (\w+) now also picks up scoped/test/annotation configs.
        build = _write(
            tmp_path,
            "build.gradle",
            """\
            dependencies {
                testImplementation 'junit:junit:4.13.2'
                compileOnly("org.projectlombok:lombok:1.18.30")
            }
            """,
        )
        deps = scanner._read_build_gradle_file(str(build))
        names = {d["moduleName"] for d in deps}
        assert names == {"junit:junit", "org.projectlombok:lombok"}

    def test_all_entries_marked_direct(self, scanner: SBOMScanner, tmp_path: Path, license_stub):
        build = _write(
            tmp_path, "build.gradle", "implementation 'a.b:c:1.0'\n"
        )
        deps = scanner._read_build_gradle_file(str(build))
        assert deps[0]["dependency_type"] == "direct"


class TestReadGradleLockfile:
    def test_all_entries_are_direct(
        self, scanner: SBOMScanner, tmp_path: Path, license_stub
    ):
        """cvedb-fetcher has no gradle.lockfile parser - its gradle
        dependencies always default to "direct" - so zyloch matches that
        instead of guessing at a transitive split cvedb-fetcher doesn't
        make."""
        lockfile = _write(
            tmp_path,
            "gradle.lockfile",
            """\
            # This is a Gradle generated file for dependency locking.
            com.google.guava:guava:33.0.0-jre=compileClasspath,runtimeClasspath
            com.google.guava:failureaccess:1.0.1=compileClasspath,runtimeClasspath
            empty=annotationProcessor
            """,
        )
        deps = scanner._read_gradle_lockfile(str(lockfile))
        by_name = {d["moduleName"]: d["dependency_type"] for d in deps}

        assert by_name["com.google.guava:guava"] == "direct"
        assert by_name["com.google.guava:failureaccess"] == "direct"
        assert len(deps) == 2  # "empty=" line must not be parsed as a coordinate

    def test_repeated_coordinate_across_configurations_is_deduped(
        self, scanner: SBOMScanner, tmp_path: Path, license_stub
    ):
        lockfile = _write(
            tmp_path,
            "gradle.lockfile",
            """\
            a.b:c:1.0=compileClasspath
            a.b:c:1.0=runtimeClasspath
            a.b:c:1.0=testCompileClasspath
            """,
        )
        deps = scanner._read_gradle_lockfile(str(lockfile))
        assert len(deps) == 1


class TestReadJavaGradleDependenciesOrchestration:
    def test_uses_lockfile_when_present_all_entries_direct(
        self, scanner: SBOMScanner, tmp_path: Path, license_stub
    ):
        build = _write(
            tmp_path, "build.gradle", "implementation 'com.google.guava:guava:33.0.0-jre'\n"
        )
        lockfile = _write(
            tmp_path,
            "gradle.lockfile",
            "com.google.guava:guava:33.0.0-jre=compileClasspath\n"
            "com.google.guava:failureaccess:1.0.1=compileClasspath\n",
        )
        deps = scanner._read_java_gradle_dependencies(
            {"java_gradle": [str(build), str(lockfile)]}, str(tmp_path)
        )
        by_name = {d["moduleName"]: d["dependency_type"] for d in deps}

        assert by_name["com.google.guava:guava"] == "direct"
        assert by_name["com.google.guava:failureaccess"] == "direct"

    def test_falls_back_to_build_file_when_no_lockfile_present(
        self, scanner: SBOMScanner, tmp_path: Path, license_stub
    ):
        build = _write(tmp_path, "build.gradle", "implementation 'a.b:c:1.0'\n")
        deps = scanner._read_java_gradle_dependencies({"java_gradle": [str(build)]}, str(tmp_path))
        assert len(deps) == 1
        assert deps[0]["dependency_type"] == "direct"


class TestReadPackageJson:
    def test_production_is_direct_development_is_dev(
        self, scanner: SBOMScanner, tmp_path: Path, license_stub
    ):
        pkg = _write(
            tmp_path,
            "package.json",
            json.dumps({"dependencies": {"lodash": "^4.17.21"}, "devDependencies": {"jest": "^29.0.0"}}),
        )
        deps = scanner._read_package_json(str(pkg))
        by_name = {d["moduleName"]: d for d in deps}

        assert by_name["lodash"]["dependencyType"] == "production"
        assert by_name["jest"]["dependencyType"] == "development"
        assert by_name["lodash"]["dependency_type"] == "direct"
        assert by_name["jest"]["dependency_type"] == "dev"

    def test_optional_dependencies_are_direct(
        self, scanner: SBOMScanner, tmp_path: Path, license_stub
    ):
        pkg = _write(
            tmp_path,
            "package.json",
            json.dumps({"optionalDependencies": {"fsevents": "^2.3.0"}}),
        )
        deps = scanner._read_package_json(str(pkg))

        assert deps[0]["dependencyType"] == "optional"
        assert deps[0]["dependency_type"] == "direct"


class TestReadPackageLockJson:
    def test_root_deps_are_direct_rest_are_transitive(
        self, scanner: SBOMScanner, tmp_path: Path, license_stub
    ):
        lock = _write(
            tmp_path,
            "package-lock.json",
            json.dumps(
                {
                    "lockfileVersion": 3,
                    "packages": {
                        "": {"dependencies": {"express": "^4.18.0"}},
                        "node_modules/express": {"version": "4.18.2"},
                        "node_modules/express/node_modules/debug": {"version": "2.6.9"},
                    },
                }
            ),
        )
        deps = scanner._read_package_lock_json(str(lock))
        by_name = {d["moduleName"]: d["dependency_type"] for d in deps}

        assert by_name["express"] == "direct"
        assert by_name["debug"] == "transitive"

    def test_dev_flag_maps_to_development_scope_type(
        self, scanner: SBOMScanner, tmp_path: Path, license_stub
    ):
        lock = _write(
            tmp_path,
            "package-lock.json",
            json.dumps(
                {
                    "packages": {
                        "": {"devDependencies": {"jest": "^29.0.0"}},
                        "node_modules/jest": {"version": "29.7.0", "dev": True},
                    }
                }
            ),
        )
        deps = scanner._read_package_lock_json(str(lock))
        assert deps[0]["dependencyType"] == "development"
        assert deps[0]["dependency_type"] == "dev"

    def test_nested_dev_package_is_transitive_not_dev(
        self, scanner: SBOMScanner, tmp_path: Path, license_stub
    ):
        """A "dev": true flag only means top-level dev dependency; once nested
        under another package's node_modules/ it's transitive, matching
        cvedb-fetcher's parse_package_lock_json is_nested handling."""
        lock = _write(
            tmp_path,
            "package-lock.json",
            json.dumps(
                {
                    "packages": {
                        "": {"devDependencies": {"jest": "^29.0.0"}},
                        "node_modules/jest": {"version": "29.7.0", "dev": True},
                        "node_modules/jest/node_modules/glob": {"version": "7.2.3", "dev": True},
                    }
                }
            ),
        )
        deps = scanner._read_package_lock_json(str(lock))
        by_name = {d["moduleName"]: d["dependency_type"] for d in deps}

        assert by_name["jest"] == "dev"
        assert by_name["glob"] == "transitive"

    def test_lockfile_version_1_without_packages_key_returns_empty(
        self, scanner: SBOMScanner, tmp_path: Path, license_stub
    ):
        lock = _write(
            tmp_path,
            "package-lock.json",
            json.dumps({"lockfileVersion": 1, "dependencies": {"express": {"version": "4.18.2"}}}),
        )
        assert scanner._read_package_lock_json(str(lock)) == []


class TestReadJavascriptDependenciesOrchestration:
    def test_uses_lockfile_split_when_present(self, scanner: SBOMScanner, tmp_path: Path, license_stub):
        pkg = _write(tmp_path, "package.json", json.dumps({"dependencies": {"express": "^4.18.0"}}))
        _write(
            tmp_path,
            "package-lock.json",
            json.dumps(
                {
                    "packages": {
                        "": {"dependencies": {"express": "^4.18.0"}},
                        "node_modules/express": {"version": "4.18.2"},
                        "node_modules/debug": {"version": "2.6.9"},
                    }
                }
            ),
        )
        file_map = {"javascript": [str(pkg), str(tmp_path / "package-lock.json")]}
        deps = scanner._read_javascript_dependencies(file_map, str(tmp_path))
        names = {d["moduleName"] for d in deps}
        assert names == {"express", "debug"}

    def test_falls_back_to_package_json_when_lockfile_is_old_format(
        self, scanner: SBOMScanner, tmp_path: Path, license_stub
    ):
        pkg = _write(tmp_path, "package.json", json.dumps({"dependencies": {"express": "^4.18.0"}}))
        _write(
            tmp_path,
            "package-lock.json",
            json.dumps({"lockfileVersion": 1, "dependencies": {"express": {"version": "4.18.2"}}}),
        )
        file_map = {"javascript": [str(pkg), str(tmp_path / "package-lock.json")]}
        deps = scanner._read_javascript_dependencies(file_map, str(tmp_path))

        assert len(deps) == 1
        assert deps[0]["moduleName"] == "express"
        assert deps[0]["dependency_type"] == "direct"

    def test_falls_back_to_package_json_when_no_lockfile_present(
        self, scanner: SBOMScanner, tmp_path: Path, license_stub
    ):
        pkg = _write(tmp_path, "package.json", json.dumps({"dependencies": {"express": "^4.18.0"}}))
        deps = scanner._read_javascript_dependencies({"javascript": [str(pkg)]}, str(tmp_path))
        assert len(deps) == 1
        assert deps[0]["moduleName"] == "express"


class TestReadGoDependenciesIndirectMarker:
    """cvedb-fetcher's parse_go_mod never reads the "// indirect" marker -
    every go.mod entry it emits defaults to "direct" - so zyloch matches
    that instead of guessing at a transitive split cvedb-fetcher doesn't
    make."""

    def test_indirect_comment_is_still_direct(self, scanner: SBOMScanner, tmp_path: Path, license_stub):
        go_mod = _write(
            tmp_path,
            "go.mod",
            """\
            module example.com/demo

            go 1.21

            require (
                github.com/gin-gonic/gin v1.9.1
                golang.org/x/sys v0.16.0 // indirect
            )
            """,
        )
        deps = scanner._read_go_dependencies({"go": [str(go_mod)]}, str(tmp_path))
        by_name = {d["moduleName"]: d["dependency_type"] for d in deps}

        assert by_name["github.com/gin-gonic/gin"] == "direct"
        assert by_name["golang.org/x/sys"] == "direct"

    def test_single_line_require_with_indirect_comment_is_still_direct(
        self, scanner: SBOMScanner, tmp_path: Path, license_stub
    ):
        go_mod = _write(
            tmp_path,
            "go.mod",
            """\
            module example.com/demo

            go 1.21

            require github.com/gin-gonic/gin v1.9.1
            require golang.org/x/sys v0.16.0 // indirect
            """,
        )
        deps = scanner._read_go_dependencies({"go": [str(go_mod)]}, str(tmp_path))
        by_name = {d["moduleName"]: d["dependency_type"] for d in deps}

        assert by_name["github.com/gin-gonic/gin"] == "direct"
        assert by_name["golang.org/x/sys"] == "direct"

    def test_other_trailing_comments_do_not_trigger_transitive(
        self, scanner: SBOMScanner, tmp_path: Path, license_stub
    ):
        go_mod = _write(
            tmp_path,
            "go.mod",
            """\
            module example.com/demo

            go 1.21

            require (
                github.com/gin-gonic/gin v1.9.1 // pinned for CVE-2023-xxxx
            )
            """,
        )
        deps = scanner._read_go_dependencies({"go": [str(go_mod)]}, str(tmp_path))
        assert deps[0]["dependency_type"] == "direct"


class TestDependencyTypeInFormattedOutput:
    def test_dependency_type_flows_into_formatted_output(self, scanner: SBOMScanner):
        deps = [
            {
                "moduleName": "requests",
                "versionInfo": "2.31.0",
                "packageManager": "pypi",
                "licenseConcluded": "MIT",
                "sha": "abc",
                "sourceLocation": "Pipfile.lock",
                "packageURL": "https://pypi.org/project/requests/",
                "dependency_type": "transitive",
            }
        ]
        entry = scanner._build_sbom_formatted_output(deps)[0]
        assert entry["dependency_type"] == "transitive"

    def test_dependency_type_is_none_when_source_gave_no_signal(self, scanner: SBOMScanner):
        deps = [
            {
                "moduleName": "orphan",
                "versionInfo": "1.0.0",
                "packageManager": "unknown",
                "licenseConcluded": "-",
                "sha": "Unknown",
                "sourceLocation": "sbom.json",
                "packageURL": "Unknown",
            }
        ]
        entry = scanner._build_sbom_formatted_output(deps)[0]
        assert entry["dependency_type"] is None
