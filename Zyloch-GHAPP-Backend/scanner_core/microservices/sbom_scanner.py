import os
import sys
import time
import json
import re
import tomllib
import xml.etree.ElementTree as ET
from typing import List, Dict, Any, Optional, Set, Tuple
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner_core.base_scanner import (
    BaseScanner, ScanRequest, ScanResponse, ScanResult,
    ScanFinding, ScanStatus, ScanSeverity
)
from scanner_core.logging_config import get_scanner_logger
from scanner_core.helpers.sbom_mongo_utils import (
    get_package_by_name,
    get_sbom_database,
    ensure_sbom_mongo_connection,
    SBOMMongoConnectionError,
    SBOM_MONGO_CONNECTION_FAILED_USER_MESSAGE,
)
from scanner_core.helpers.cve_finder import bulk_find_vulnerabilities
from scanner_core.helpers.license_risk import get_license_risk_level
from scanner_core.helpers.eol_checker import (
    parse_go_version,
    normalize_java_current_version,
    parse_maven_java_version,
    parse_gradle_java_version,
    parse_gradle_wrapper_version,
    parse_maven_wrapper_version,
    parse_engines_node_version,
    parse_nvmrc_version,
    parse_python_version_from_requirements,
    parse_pipfile_python_version,
    parse_pyproject_python_version,
    parse_required_providers_from_tf,
    parse_provider_blocks_from_tf,
    parse_terraform_lock_providers,
    parse_terraform_required_version,
    terraform_provider_key,
    check_eol_for_versions_with_origins,
)

logger = get_scanner_logger()


# ---------------------------------------------------------------------------
# Official package registry URL builders
# ---------------------------------------------------------------------------

def _build_pypi_url(name: str, version: Optional[str] = None) -> str:
    if version:
        return f"https://pypi.org/project/{name}/{version}/"
    return f"https://pypi.org/project/{name}/"


def _build_npm_url(name: str, version: Optional[str] = None) -> str:
    if version:
        return f"https://www.npmjs.com/package/{name}/v/{version}"
    return f"https://www.npmjs.com/package/{name}"


def _build_go_url(name: str, version: Optional[str] = None) -> str:
    if version:
        go_version = version if version.startswith("v") else f"v{version}"
        return f"https://pkg.go.dev/{name}@{go_version}"
    return f"https://pkg.go.dev/{name}"


def _build_maven_url(name: str, version: Optional[str] = None) -> str:
    """Build MVN Repository URL from 'groupId:artifactId' or plain artifactId."""
    if ":" in name:
        group_id, artifact_id = name.split(":", 1)
        base = f"https://mvnrepository.com/artifact/{group_id}/{artifact_id}"
    else:
        base = f"https://mvnrepository.com/artifact/{name}"
    return f"{base}/{version}" if version else base


class SBOMScanner(BaseScanner):
    def __init__(self):
        super().__init__("sbom")
        self.file_types = {
            "python": ["requirements.txt", "Pipfile", "pyproject.toml", "Pipfile.lock", "poetry.lock"],
            "java_maven": ["pom.xml"],
            "java_gradle": ["build.gradle", "build.gradle.kts", "gradle.lockfile"],
            "javascript": ["package.json", "package-lock.json"],
            "go": ["go.mod"]
        }
        
        self._sbom_count_only = False
        self._sbom_progress_total = 0
        self._sbom_progress_current = 0
        self._sbom_progress_half_logged = False
        self._sbom_progress_complete_logged = False

    def scan(self, request: ScanRequest) -> ScanResponse:
        """Execute SBOM scan to detect dependencies and fetch metadata"""
        start_time = time.time()

        try:
            logger.info(f"Starting SBOM scan for: {request.repo_path}")

            # SBOM scan requires Intel/SBOM MongoDB. Fail fast if unreachable.
            try:
                ensure_sbom_mongo_connection()
                db = get_sbom_database()
                try:
                    collections = db.list_collection_names()
                    logger.info(
                        "SBOM MongoDB connected (%s collection(s))",
                        len(collections) if collections is not None else 0,
                    )
                    print(f"[SBOM] MongoDB connected. Collections: {collections}")
                except Exception as list_error:
                    logger.warning(
                        "Could not list SBOM MongoDB collections (may be permissions issue): %s",
                        list_error,
                    )
                    print(f"[SBOM WARNING] Could not list collections: {list_error}")
            except SBOMMongoConnectionError as mongo_error:
                logger.error(
                    "SBOM MongoDB connection failed: %s", mongo_error, exc_info=True
                )
                print(f"[SBOM ERROR] {SBOM_MONGO_CONNECTION_FAILED_USER_MESSAGE}")
                return self._create_error_response(
                    request.scan_id,
                    SBOM_MONGO_CONNECTION_FAILED_USER_MESSAGE,
                )

            # Scan for dependency files
            file_map = self._scan_files(request.repo_path)

            # Detect runtime/build tool versions and check EOL status
            runtime_versions, runtime_version_origins, tf_provider_meta = (
                self._detect_runtime_versions(file_map, request.repo_path)
            )
            eol_results = self._check_eol_status(
                runtime_versions, runtime_version_origins, tf_provider_meta
            )

            if not any(file_map.values()):
                logger.info("No dependency files found")
                normalized_eol_empty = self._normalize_eol_paths(
                    eol_results, request.repo_path
                )
                tf_providers_empty = normalized_eol_empty.pop(
                    "terraformProviders", None
                )
                metadata = {
                    "total_packages": 0,
                    "total_package_managers": 0,
                    "unique_license_types": 0,
                    "unknown_licenses_count": 0,
                    "legal_review_required": False,
                    "eol": normalized_eol_empty,
                }
                if tf_providers_empty:
                    metadata["terraformProviders"] = tf_providers_empty
                return self._create_success_response(
                    request.scan_id,
                    ScanResult(
                        scanner_type=self.scanner_type,
                        status=ScanStatus.COMPLETED,
                        findings=[],
                        scanned_files=[],
                        scan_duration=time.time() - start_time,
                        metadata=metadata
                    )
                )

            dependencies = self._extract_all_dependencies(file_map, request.repo_path)
            dependencies = self._normalize_dependency_paths(dependencies, request.repo_path)

            # Calculate statistics
            stats = self._calculate_statistics(dependencies)

            # Enrich dependencies with SPDX + CycloneDX stacks
            enriched = self._build_sbom_formatted_output(
                dependencies, request.repo_path
            )
            stats["dependencies"] = enriched

            # Write SPDX and CycloneDX files to output_dir at runtime
            if request.output_dir:
                try:
                    self._write_sbom_files(enriched, request.scan_id, request.output_dir)
                except Exception as write_err:
                    logger.warning("Failed to write SBOM files: %s", write_err)

            # EOL runtimes/tools; Terraform providers live on stats["terraformProviders"]
            normalized_eol = self._normalize_eol_paths(eol_results, request.repo_path)
            tf_providers = normalized_eol.pop("terraformProviders", None)
            stats["eol"] = normalized_eol
            if tf_providers:
                stats["terraformProviders"] = tf_providers

            # Convert dependencies to findings
            findings = self._dependencies_to_findings(dependencies)

            # Get scanned files list
            scanned_files = []
            for file_list in file_map.values():
                scanned_files.extend(file_list)
            scanned_files = [self._to_repo_relative_path(path, request.repo_path) for path in scanned_files]

            scan_duration = time.time() - start_time

            logger.info(
                f"SBOM scan completed: {stats['total_packages']} packages found "
                f"across {stats['total_package_managers']} package managers"
            )

            return self._create_success_response(
                request.scan_id,
                ScanResult(
                    scanner_type=self.scanner_type,
                    status=ScanStatus.COMPLETED,
                    findings=findings,
                    scanned_files=scanned_files,
                    scan_duration=scan_duration,
                    metadata=stats
                )
            )

        except SBOMMongoConnectionError:
            logger.error(
                "SBOM MongoDB connection failed during scan", exc_info=True
            )
            return self._create_error_response(
                request.scan_id,
                SBOM_MONGO_CONNECTION_FAILED_USER_MESSAGE,
            )
        except Exception as e:
            logger.error(f"SBOM scan failed: {e}", exc_info=True)
            return self._create_error_response(
                request.scan_id,
                f"SBOM scan failed: {str(e)}"
            )

    @staticmethod
    def _to_repo_relative_path(path: str, repo_path: str) -> str:
        
        if not path or not isinstance(path, str):
            return path

        repo_name = os.path.basename(os.path.normpath(repo_path))

        # Normalize slashes
        normalized_path = path.replace("\\", "/")
        normalized_repo = repo_path.replace("\\", "/").rstrip("/")

        if normalized_path.startswith(normalized_repo + "/"):
            return normalized_path[len(normalized_repo) + 1 :]

        marker = f"/{repo_name}/"
        if marker in normalized_path:
            return normalized_path.split(marker, 1)[1]

        try:
            rel = os.path.relpath(path, repo_path).replace("\\", "/")
            if rel and rel != "." and not rel.startswith(".."):
                return rel
        except Exception:
            pass

        return normalized_path

    def _normalize_dependency_paths(
        self, dependencies: List[Dict[str, Any]], repo_path: str
    ) -> List[Dict[str, Any]]:
        for dep in dependencies:
            source_location = dep.get("sourceLocation")
            if source_location:
                dep["sourceLocation"] = self._to_repo_relative_path(source_location, repo_path)
        return dependencies

    def _normalize_eol_paths(
        self, eol_results: Dict[str, Optional[dict]], repo_path: str
    ) -> Dict[str, Optional[dict]]:
        if not isinstance(eol_results, dict):
            return eol_results

        for key, result in eol_results.items():
            # Handle nested terraformProviders block
            if key == "terraformProviders" and isinstance(result, dict):
                for _, provider_result in result.items():
                    if not isinstance(provider_result, dict):
                        continue
                    source_files = provider_result.get("source_files")
                    if isinstance(source_files, list):
                        provider_result["source_files"] = [
                            self._to_repo_relative_path(p, repo_path)
                            for p in source_files
                            if isinstance(p, str)
                        ]
                continue

            if not isinstance(result, dict):
                continue
            source_files = result.get("source_files")
            if isinstance(source_files, list):
                result["source_files"] = [
                    self._to_repo_relative_path(path, repo_path)
                    for path in source_files
                    if isinstance(path, str)
                ]
        return eol_results

    # ---------------------------------------------------------------------------
    # File scanning
    # ---------------------------------------------------------------------------

    def _scan_files(self, project_path: str) -> Dict[str, List[str]]:
        """Scan repository for dependency files"""
        file_map = defaultdict(list)
        for root, dirs, files in os.walk(project_path):
            dirs[:] = [d for d in dirs if not d.startswith('.')]
            for file in files:
                full_path = os.path.join(root, file)

                for category, filenames in self.file_types.items():
                    if file in filenames:
                        file_map[category].append(full_path)

                # Detect common SBOM artifact files (CycloneDX / SPDX JSON)
                lower = file.lower()
                if lower.endswith(".json") and any(
                    k in lower for k in ["cyclonedx", "spdx", "sbom", "bom"]
                ):
                    file_map["sbom_artifacts"].append(full_path)
        return file_map

    @staticmethod
    def _package_manager_from_purl(purl: str) -> str:
        """Convert a Package URL (purl) to the internal SBOM Mongo 'manager' key."""
        if not purl or not isinstance(purl, str):
            return "unknown"
        if not purl.startswith("pkg:"):
            return "unknown"
        try:
            pkg_type = purl[len("pkg:"):].split("/", 1)[0].strip().lower()
        except Exception:
            return "unknown"
        if pkg_type == "golang":
            return "go"
        return pkg_type

    def _read_sbom_artifact_dependencies(self, artifact_paths: List[str]) -> List[Dict[str, Any]]:
        """Extract dependencies from SBOM artifact files (CycloneDX/SPDX JSON)."""
        dependencies: List[Dict[str, Any]] = []

        for artifact_path in artifact_paths:
            try:
                with open(artifact_path, "r", encoding="utf-8", errors="ignore") as f:
                    data = json.load(f)
            except Exception:
                continue

            if not isinstance(data, dict):
                continue

            # -------- CycloneDX JSON --------
            bom_format = str(data.get("bomFormat", "")).lower()
            is_cyclonedx = "cyclonedx" in bom_format or (
                "components" in data and isinstance(data.get("components"), list)
            )
            if is_cyclonedx:
                components = data.get("components", []) or []
                if isinstance(components, list):
                    for comp in components:
                        if not isinstance(comp, dict):
                            continue

                        name = comp.get("name") or comp.get("componentName") or comp.get("bom-ref")
                        version = comp.get("version")
                        purl = comp.get("purl") or comp.get("packageURL") or None
                        manager = self._package_manager_from_purl(purl)
                        license_value = "-"

                        licenses = comp.get("licenses")
                        if isinstance(licenses, list) and licenses:
                            first = licenses[0]
                            if isinstance(first, dict):
                                license_obj = first.get("license") or first
                                if isinstance(license_obj, dict):
                                    license_value = (
                                        license_obj.get("id")
                                        or license_obj.get("expression")
                                        or license_obj.get("name")
                                        or "-"
                                    )
                                elif isinstance(license_obj, str):
                                    license_value = license_obj

                        dependency: Dict[str, Any] = {
                            "moduleName": name or "Unknown",
                            "versionInfo": version,
                            "sha": "Unknown",
                            "sourceLocation": artifact_path,
                            "packageURL": purl or "Unknown",
                            "packageManager": manager,
                            "licenseConcluded": license_value,
                        }
                        component_type = comp.get("type")
                        if isinstance(component_type, str) and component_type.strip():
                            dependency["componentType"] = component_type.strip().lower()

                        if (
                            dependency["packageManager"] in {"pypi", "npm", "go", "maven", "gradle"}
                            and dependency.get("moduleName")
                            and dependency.get("versionInfo")
                        ):
                            try:
                                lic, pkg_url, sha, _ = self._get_license(
                                    dependency["moduleName"],
                                    dependency["packageManager"],
                                    str(dependency["versionInfo"]),
                                )
                                dependency["licenseConcluded"] = lic
                                if pkg_url and pkg_url != "Unknown":
                                    dependency["packageURL"] = pkg_url
                                if sha:
                                    dependency["sha"] = sha
                            except Exception:
                                pass

                        dependencies.append(dependency)

                continue

            # -------- SPDX JSON --------
            is_spdx = bool(data.get("spdxVersion") or data.get("SPDXID") or data.get("packages"))
            if is_spdx:
                packages = data.get("packages", []) or []
                if isinstance(packages, list):
                    for pkg in packages:
                        if not isinstance(pkg, dict):
                            continue

                        name = pkg.get("name") or pkg.get("packageName")
                        version = pkg.get("versionInfo") or pkg.get("version")
                        license_value = pkg.get("licenseConcluded") or pkg.get("license") or "-"

                        purl = None
                        ext_refs = pkg.get("externalRefs") or pkg.get("external_refs") or []
                        if isinstance(ext_refs, list):
                            for ref in ext_refs:
                                if not isinstance(ref, dict):
                                    continue
                                ref_type = str(
                                    ref.get("referenceType") or ref.get("reference_type") or ""
                                ).lower()
                                locator = (
                                    ref.get("referenceLocator")
                                    or ref.get("reference_locator")
                                    or ref.get("locator")
                                )
                                if isinstance(locator, str) and locator.startswith("pkg:"):
                                    purl = locator
                                    break
                                if ref_type == "purl" and isinstance(locator, str) and locator.startswith("pkg:"):
                                    purl = locator
                                    break

                        manager = self._package_manager_from_purl(purl) if purl else "unknown"

                        dependency = {
                            "moduleName": name or "Unknown",
                            "versionInfo": version,
                            "sha": "Unknown",
                            "sourceLocation": artifact_path,
                            "packageURL": purl or "Unknown",
                            "packageManager": manager,
                            "licenseConcluded": license_value,
                        }

                        if (
                            dependency["packageManager"] in {"pypi", "npm", "go", "maven", "gradle"}
                            and dependency.get("moduleName")
                            and dependency.get("versionInfo")
                        ):
                            try:
                                lic, pkg_url, sha, _ = self._get_license(
                                    dependency["moduleName"],
                                    dependency["packageManager"],
                                    str(dependency["versionInfo"]),
                                )
                                dependency["licenseConcluded"] = lic
                                if pkg_url and pkg_url != "Unknown":
                                    dependency["packageURL"] = pkg_url
                                if sha:
                                    dependency["sha"] = sha
                            except Exception:
                                pass

                        dependencies.append(dependency)

        return dependencies

    def _detect_runtime_versions(
        self, file_map: Dict[str, List[str]], repo_path: str
    ) -> Tuple[
        Dict[str, List[str]],
        Dict[str, Dict[str, List[str]]],
        Dict[str, Dict[str, Optional[str]]],
    ]:
        """
        Detect runtime/build tool versions from repository files.
        """
        versions: Dict[str, Set[str]] = {
            "java": set(),
            "go": set(),
            "maven_wrapper": set(),
            "gradle_wrapper": set(),
            "npm": set(),
            "python": set(),
            "terraform": set(),
        }
        version_origins: Dict[str, Dict[str, Set[str]]] = {
            "java": {},
            "go": {},
            "maven_wrapper": {},
            "gradle_wrapper": {},
            "npm": {},
            "python": {},
            "terraform": {},
        }
        tf_provider_meta: Dict[str, Dict[str, Optional[str]]] = {}

        def record_origin(product_key: str, version: str, path: str) -> None:
            v = version.strip()
            if not v:
                return
            per_product = version_origins.setdefault(product_key, {})
            paths = per_product.setdefault(v, set())
            paths.add(path)

        # ----------- Go -----------
        for go_mod_path in file_map.get("go", []):
            try:
                with open(go_mod_path, "r", encoding="utf-8", errors="ignore") as f:
                    go_version = parse_go_version(f.read())
                    if go_version:
                        v = go_version.strip()
                        if v:
                            versions["go"].add(v)
                            record_origin("go", v, go_mod_path)
            except Exception as e:
                logger.warning(f"Error reading go.mod from {go_mod_path}: {e}")

        # ----------- Java (Maven pom.xml) -----------
        for pom_path in file_map.get("java_maven", []):
            try:
                with open(pom_path, "r", encoding="utf-8", errors="ignore") as f:
                    java_version = parse_maven_java_version(f.read())
                    if java_version:
                        vv = java_version.strip()
                        if vv == "1.8":
                            vv = "8"
                        if vv:
                            versions["java"].add(vv)
                            record_origin("java", vv, pom_path)
            except Exception as e:
                logger.warning(f"Error reading pom.xml from {pom_path}: {e}")
                continue

        # ----------- Java (Gradle build.gradle) -----------
        for gradle_path in file_map.get("java_gradle", []):
            try:
                with open(gradle_path, "r", encoding="utf-8", errors="ignore") as f:
                    java_version = parse_gradle_java_version(f.read())
                    if java_version:
                        vv = java_version.strip()
                        if vv == "1.8":
                            vv = "8"
                        if vv:
                            versions["java"].add(vv)
                            record_origin("java", vv, gradle_path)
            except Exception as e:
                logger.warning(f"Error reading build.gradle from {gradle_path}: {e}")
                continue

        if versions["java"]:
            logger.info(
                f"Detected Java version(s): {sorted(versions['java'])} from "
                f"{sum(len(p) for p in version_origins.get('java', {}).values())} file(s)"
            )

        # ----------- Gradle wrapper -----------
        gradle_wrapper_paths = []
        for root, dirs, files in os.walk(repo_path):
            dirs[:] = [d for d in dirs if not d.startswith(".")]
            for file in files:
                if file == "gradle-wrapper.properties":
                    full_path = os.path.join(root, file)
                    rel_path = os.path.relpath(full_path, repo_path)
                    if "gradle" in rel_path.lower() and "wrapper" in rel_path.lower():
                        gradle_wrapper_paths.append(full_path)

        for gradle_wrapper_path in gradle_wrapper_paths:
            try:
                with open(gradle_wrapper_path, "r", encoding="utf-8", errors="ignore") as f:
                    gradle_version = parse_gradle_wrapper_version(f.read())
                    if gradle_version:
                        v = gradle_version.strip()
                        if v:
                            versions["gradle_wrapper"].add(v)
                            record_origin("gradle_wrapper", v, gradle_wrapper_path)
                            logger.info(
                                f"Detected Gradle wrapper version: {v} from {gradle_wrapper_path}"
                            )
            except Exception as e:
                logger.warning(
                    f"Error reading gradle-wrapper.properties from {gradle_wrapper_path}: {e}"
                )

        # ----------- Maven wrapper -----------
        maven_wrapper_paths = []
        for root, dirs, files in os.walk(repo_path):
            dirs[:] = [d for d in dirs if not d.startswith(".") or d == ".mvn"]
            for file in files:
                if file == "maven-wrapper.properties":
                    full_path = os.path.join(root, file)
                    rel_path = os.path.relpath(full_path, repo_path)
                    if ".mvn" in rel_path.lower() and "wrapper" in rel_path.lower():
                        maven_wrapper_paths.append(full_path)

        for maven_wrapper_path in maven_wrapper_paths:
            try:
                with open(maven_wrapper_path, "r", encoding="utf-8", errors="ignore") as f:
                    maven_version = parse_maven_wrapper_version(f.read())
                    if maven_version:
                        v = maven_version.strip()
                        if v:
                            versions["maven_wrapper"].add(v)
                            record_origin("maven_wrapper", v, maven_wrapper_path)
            except Exception as e:
                logger.warning(
                    f"Error reading maven-wrapper.properties from {maven_wrapper_path}: {e}"
                )

        # ----------- Node.js (package.json engines.node) -----------
        for pkg_path in file_map.get("javascript", []):
            try:
                with open(pkg_path, "r", encoding="utf-8", errors="ignore") as f:
                    node_ver = parse_engines_node_version(f.read())
                    if node_ver:
                        v = node_ver.strip()
                        if v:
                            versions["npm"].add(v)
                            record_origin("npm", v, pkg_path)
            except Exception as e:
                logger.warning(f"Error reading package.json for Node version from {pkg_path}: {e}")

        # ----------- Node.js (.nvmrc / .node-version) -----------
        nvm_paths: List[str] = []
        for root, dirs, files in os.walk(repo_path):
            dirs[:] = [d for d in dirs if not d.startswith(".")]
            for file in files:
                if file in (".nvmrc", ".node-version"):
                    nvm_paths.append(os.path.join(root, file))
        for nvm_path in nvm_paths:
            try:
                with open(nvm_path, "r", encoding="utf-8", errors="ignore") as f:
                    node_ver = parse_nvmrc_version(f.read())
                    if node_ver:
                        v = node_ver.strip()
                        if v:
                            versions["npm"].add(v)
                            record_origin("npm", v, nvm_path)
            except Exception as e:
                logger.warning(f"Error reading {nvm_path}: {e}")

        # ----------- Python runtime -----------
        for py_path in file_map.get("python", []):
            try:
                base = os.path.basename(py_path).lower()
                with open(py_path, "r", encoding="utf-8", errors="ignore") as f:
                    text = f.read()

                python_ver: Optional[str] = None
                if base == "requirements.txt":
                    python_ver = parse_python_version_from_requirements(text)
                elif base == "pipfile":
                    python_ver = parse_pipfile_python_version(text)
                elif base == "pyproject.toml":
                    python_ver = parse_pyproject_python_version(text)

                if python_ver:
                    v = python_ver.strip()
                    if v:
                        versions["python"].add(v)
                        record_origin("python", v, py_path)
            except Exception as e:
                logger.warning(f"Error reading Python runtime version from {py_path}: {e}")

        # ----------- Terraform providers -----------
        terraform_providers_with_explicit_versions: Set[str] = set()
        terraform_provider_declared_files: Dict[str, Set[str]] = {}
        lockfile_paths: List[str] = []

        # Phase 1: scan every .tf file in the repo tree
        for root, dirs, files in os.walk(repo_path):
            dirs[:] = [d for d in dirs if not d.startswith(".")]
            for file in files:
                full_path = os.path.join(root, file)

                if file.endswith(".tf"):
                    try:
                        with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                            tf_text = f.read()
                            tf_core_ver = parse_terraform_required_version(tf_text)
                            if tf_core_ver:
                                v = tf_core_ver.strip()
                                if v:
                                    versions["terraform"].add(v)
                                    record_origin("terraform", v, full_path)
                            providers = parse_required_providers_from_tf(tf_text)
                            legacy_provider_blocks = parse_provider_blocks_from_tf(tf_text)

                        providers.extend(legacy_provider_blocks)

                        for provider in providers:
                            block_label = (provider.get("block_label") or "").strip()
                            source = (provider.get("source") or "").strip()

                            if not block_label and not source:
                                continue

                            provider_key = terraform_provider_key(block_label, source)

                            declared_paths = terraform_provider_declared_files.setdefault(
                                provider_key, set()
                            )
                            declared_paths.add(full_path)

                            if provider_key not in tf_provider_meta:
                                tf_provider_meta[provider_key] = {
                                    "source": source or None,
                                }
                            else:
                                existing = tf_provider_meta[provider_key]
                                if not existing.get("source") and source:
                                    existing["source"] = source

                            version_token = (provider.get("version_token") or "").strip()
                            if not version_token:
                                continue

                            terraform_providers_with_explicit_versions.add(provider_key)
                            versions.setdefault(provider_key, set()).add(version_token)
                            record_origin(provider_key, version_token, full_path)

                    except Exception as e:
                        logger.warning(
                            f"Error reading Terraform providers from {full_path}: {e}"
                        )

                elif file == ".terraform.lock.hcl":
                    lockfile_paths.append(full_path)

        # Phase 2: process lockfiles — always prefer the locked (exact) version over
        for lock_path in lockfile_paths:
            try:
                with open(lock_path, "r", encoding="utf-8", errors="ignore") as f:
                    lock_versions = parse_terraform_lock_providers(f.read())

                for source_key, data in lock_versions.items():
                    lock_source = data.get("source") or source_key
                    provider_tail = source_key.rsplit("/", 1)[-1]
                    provider_key = terraform_provider_key(provider_tail, source_key)

                    version_token = (data.get("version_token") or "").strip()
                    if not version_token:
                        continue

                    if provider_key in terraform_providers_with_explicit_versions:
                        old_versions = versions.get(provider_key, set())
                        constraint_versions = {
                            v for v in old_versions
                            if any(op in v for op in ("~>", ">=", "<=", "!=", ">", "<", "="))
                            or not v[0].isdigit()
                        }
                        if constraint_versions:
                            versions[provider_key] = (old_versions - constraint_versions) | {version_token}
                            for old_v in constraint_versions:
                                version_origins.get(provider_key, {}).pop(old_v, None)
                        else:
                            versions.setdefault(provider_key, set()).add(version_token)

                        # Always record the lockfile as a source file
                        record_origin(provider_key, version_token, lock_path)
                        # Backfill declared .tf files under the exact locked version
                        for declared_file in terraform_provider_declared_files.get(provider_key, set()):
                            record_origin(provider_key, version_token, declared_file)
                    else:
                        
                        versions.setdefault(provider_key, set()).add(version_token)

                        if provider_key not in tf_provider_meta:
                            tf_provider_meta[provider_key] = {"source": lock_source}
                        else:
                            existing = tf_provider_meta[provider_key]
                            if not existing.get("source") and lock_source:
                                existing["source"] = lock_source

                        for declared_file in terraform_provider_declared_files.get(provider_key, set()):
                            record_origin(provider_key, version_token, declared_file)
                        record_origin(provider_key, version_token, lock_path)

            except Exception as e:
                logger.warning(f"Error reading Terraform lockfile from {lock_path}: {e}")

        # ----------- Serialise sets -> sorted lists -----------
        versions_out: Dict[str, List[str]] = {
            key: sorted(list(value)) for key, value in versions.items() if value
        }
        origins_out: Dict[str, Dict[str, List[str]]] = {
            product_key: {
                ver: sorted(list(paths))
                for ver, paths in per_product.items()
                if paths
            }
            for product_key, per_product in version_origins.items()
            if per_product
        }

        return versions_out, origins_out, tf_provider_meta

    # ---------------------------------------------------------------------------
    # EOL checking
    # ---------------------------------------------------------------------------

    def _check_eol_status(
        self,
        versions: Dict[str, List[str]],
        origins: Dict[str, Dict[str, List[str]]],
        tf_provider_meta: Optional[Dict[str, Dict[str, Optional[str]]]] = None,
    ) -> Dict[str, Optional[dict]]:
        try:
            eol_results = check_eol_for_versions_with_origins(
                versions,
                origins,
                terraform_provider_meta=tf_provider_meta,
            )
            logger.info(
                f"EOL check completed for {sum(len(v) for v in versions.values())} "
                f"detected version(s)"
            )
            return eol_results
        except Exception as e:
            logger.warning(f"Error checking EOL status: {e}", exc_info=True)
            return {}

    # ---------------------------------------------------------------------------
    # License / metadata lookup
    # ---------------------------------------------------------------------------

    @staticmethod
    def _maven_mongo_license_names(package_data: Any, result: Any) -> List[str]:
        """License display strings from Maven/Gradle IntelDB Mongo documents."""
        names: List[str] = []

        def add_entry(entry: Any) -> None:
            if entry is None:
                return
            if isinstance(entry, str):
                s = entry.strip()
                if s:
                    names.append(s)
                return
            if isinstance(entry, dict):
                label = entry.get("name") or entry.get("id")
                if label is not None:
                    s = str(label).strip()
                    if s:
                        names.append(s)

        def add_raw(raw: Any) -> None:
            if raw is None:
                return
            if isinstance(raw, str):
                add_entry(raw)
            elif isinstance(raw, dict):
                add_entry(raw)
            elif isinstance(raw, list):
                for item in raw:
                    add_entry(item)

        if isinstance(package_data, dict):
            add_raw(package_data.get("licenses"))
            lic = package_data.get("license")
            if isinstance(lic, list):
                add_raw(lic)
            else:
                add_entry(lic)
            inner = package_data.get("object")
            if isinstance(inner, dict):
                add_raw(inner.get("licenses"))
                lic2 = inner.get("license")
                if isinstance(lic2, list):
                    add_raw(lic2)
                else:
                    add_entry(lic2)

        if isinstance(result, dict):
            add_raw(result.get("licenses"))
            lic = result.get("license")
            if isinstance(lic, list):
                add_raw(lic)
            else:
                add_entry(lic)

        return names

    @staticmethod
    def _is_empty_license(value: Any) -> bool:
        """Return True if the license value should be treated as unknown/missing."""
        if value is None:
            return True
        s = str(value).strip().lower()
        return s in {"", "unknown", "none", "null", "-", "noassertion", "noassertion"}

    def _log_sbom_progress(self) -> None:
        """Log once at ~50% and once at 100% of the scan-wide package total,
        instead of once per package. Total comes from the dry-run counting
        pass in _extract_all_dependencies."""
        total = self._sbom_progress_total
        if not total:
            return
        current = self._sbom_progress_current
        halfway = (total + 1) // 2
        if not self._sbom_progress_half_logged and current >= halfway:
            self._sbom_progress_half_logged = True
            msg = f"[SBOM] Scanned {current}/{total} packages (~50%)"
            logger.info(msg)
            print(msg)
        if not self._sbom_progress_complete_logged and current >= total:
            self._sbom_progress_complete_logged = True
            msg = f"[SBOM] Scanned {current}/{total} packages (100%, complete)"
            logger.info(msg)
            print(msg)

    def _get_license(
        self, name: str, manager: str, version: Optional[str] = None
    ) -> Tuple[str, str, str, Optional[str]]:
        """Get license, package URL, SHA, and (PyPI only) Mongo-backed version.

        Rules:
        - licenseConcluded: use "-" whenever data is missing/unknown (never "Unknown")
        - packageURL: always return the official registry URL even when not in MongoDB
        """
        self._sbom_progress_current += 1
        if self._sbom_count_only:
            return "-", "", "Unknown", None

        self._log_sbom_progress()

        try:
            # ------------------------------------------------------------------
            # PyPI
            # ------------------------------------------------------------------
            if manager == "pypi":
                fallback_url = _build_pypi_url(name, version)
                normalized_name = name.lower()
                result = get_package_by_name("pypi", normalized_name)

                if not result and name != normalized_name:
                    logger.debug(f"Trying original case for package: {name}")
                    result = get_package_by_name("pypi", name)

                if not result:
                    logger.debug(
                        "PyPI package not in SBOM MongoDB: %s/%s (tried %s)",
                        manager, normalized_name, name,
                    )
                    return "-", fallback_url, "Unknown", None

                package_data = result.get("object") if isinstance(result, dict) and "object" in result else result
                rendered_info = (
                    package_data.get("info", {}) if isinstance(package_data, dict) else {}
                )
                if not isinstance(rendered_info, dict):
                    rendered_info = {}

                declared: Optional[str] = None
                if version is not None:
                    s = str(version).strip()
                    if s:
                        declared = s

                effective_version = declared
                if not effective_version and isinstance(package_data, dict):
                    raw_v = package_data.get("version")
                    if raw_v is not None and str(raw_v).strip():
                        effective_version = str(raw_v).strip()
                if not effective_version:
                    raw_v = rendered_info.get("version")
                    if raw_v is not None and str(raw_v).strip():
                        effective_version = str(raw_v).strip()

                license_val = rendered_info.get("license")
                if self._is_empty_license(license_val):
                    license_val = rendered_info.get("license_expression")
                license_str = "-"
                if not self._is_empty_license(license_val) and isinstance(license_val, str):
                    license_str = license_val.split("\n")[0].strip()[:30]

                # packageURL: always the official, version-specific registry page -
                # PyPI's own stored package_url (info.package_url) is only ever the
                # generic project page, never per-version, so it's not used here.
                # Rebuilt with effective_version so a package with no declared
                # version still links to the Mongo-resolved one, not the bare page.
                package_url = _build_pypi_url(name, effective_version) if effective_version else fallback_url

                sha = "Unknown"
                if effective_version:
                    releases = package_data.get("releases", {}) if isinstance(package_data, dict) else {}
                    if releases:
                        version_releases = releases.get(effective_version, [])
                        if not version_releases:
                            normalized_version = effective_version.strip()
                            if normalized_version != effective_version and normalized_version in releases:
                                version_releases = releases[normalized_version]

                        if version_releases and len(version_releases) > 0:
                            sha_found = "Unknown"
                            for rel in version_releases:
                                if not isinstance(rel, dict):
                                    continue
                                digests = rel.get("digests", {}) or {}
                                candidate = (
                                    digests.get("sha256")
                                    or digests.get("md5")
                                    or digests.get("sha1")
                                )
                                if candidate:
                                    sha_found = candidate
                                    break
                            sha = sha_found
                        else:
                            available_versions = list(releases.keys())
                            matching_versions = [
                                v for v in available_versions if v.startswith(effective_version)
                            ]
                            if matching_versions:
                                closest_version = matching_versions[0]
                                version_releases = releases[closest_version]
                                if version_releases and len(version_releases) > 0:
                                    sha_found = "Unknown"
                                    for rel in version_releases:
                                        if not isinstance(rel, dict):
                                            continue
                                        digests = rel.get("digests", {}) or {}
                                        candidate = (
                                            digests.get("sha256")
                                            or digests.get("md5")
                                            or digests.get("sha1")
                                        )
                                        if candidate:
                                            sha_found = candidate
                                            break
                                    sha = sha_found

                if sha == "Unknown" and isinstance(result, dict):
                    doc_sha = result.get("sha")
                    if isinstance(doc_sha, str) and doc_sha.strip():
                        sha = doc_sha.strip()

                mongo_filled = bool(effective_version and not declared)
                resolved_for_output = effective_version if mongo_filled else None

                return license_str, package_url, sha, resolved_for_output

            # ------------------------------------------------------------------
            # npm
            # ------------------------------------------------------------------
            elif manager == "npm":
                version_clean = version.lstrip("^") if version else None
                fallback_url = _build_npm_url(name, version_clean)
                result = get_package_by_name("npm", name)

                if not result:
                    return "-", fallback_url, "Unknown", None

                package_data = result.get("object") if isinstance(result, dict) and "object" in result else result
                if not isinstance(package_data, dict):
                    package_data = {}

                raw_license = package_data.get("license")
                license_str = "-" if self._is_empty_license(raw_license) else str(raw_license).strip()

                # packageURL: always the official, version-specific registry page -
                # any stored package_url/repository link is never version-specific.
                package_url = fallback_url

                sha = "Unknown"
                if version_clean:
                    versions_map = package_data.get("versions", {})
                    version_data = versions_map.get(version_clean, {})
                    if version_data:
                        dist = version_data.get("dist", {})
                        sha = dist.get("shasum", "Unknown")

                return license_str, package_url, sha, None

            # ------------------------------------------------------------------
            # Go
            # ------------------------------------------------------------------
            elif manager == "go":
                fallback_url = _build_go_url(name, version)
                result = get_package_by_name("go", name)

                if not result:
                    logger.warning(f"Go package not found in SBOM MongoDB: {name}")
                    return "-", fallback_url, "Unknown", None

                package_data = result.get("object") if isinstance(result, dict) and "object" in result else result

                # packageURL: always the official, version-specific registry page.
                package_url = fallback_url

                license_str = "-"
                if isinstance(package_data, dict):
                    def _extract_go_license(pkg: dict) -> Optional[str]:
                        for field in ("license", "license_expression"):
                            val = pkg.get(field)
                            if isinstance(val, str) and val.strip() and not SBOMScanner._is_empty_license(val):
                                return val.strip()
                            if isinstance(val, list) and val:
                                s = str(val[0]).strip()
                                if not SBOMScanner._is_empty_license(s):
                                    return s
                            if isinstance(val, dict):
                                label = val.get("name") or val.get("type")
                                if label and not SBOMScanner._is_empty_license(label):
                                    return str(label).strip()
                        licenses_list = pkg.get("licenses", [])
                        if isinstance(licenses_list, list) and licenses_list:
                            item = licenses_list[0]
                            if isinstance(item, dict):
                                label = item.get("name") or item.get("type")
                                if label:
                                    return str(label).strip()
                            if isinstance(item, str) and item.strip():
                                return item.strip()
                        info = pkg.get("info", {})
                        if isinstance(info, dict):
                            val = info.get("license")
                            if isinstance(val, str) and val.strip() and not SBOMScanner._is_empty_license(val):
                                return val.strip()
                        return None

                    found = _extract_go_license(package_data)
                    if found:
                        if "\n" in found:
                            found = found.split("\n")[0].strip()
                        license_str = found[:50]

                sha = "Unknown"
                if isinstance(package_data, dict):
                    sha = (
                        package_data.get("sha")
                        or package_data.get("sha256")
                        or package_data.get("sha1")
                        or package_data.get("hash")
                        or "Unknown"
                    )

                    if version and sha == "Unknown":
                        releases = package_data.get("releases", {})
                        versions_map = package_data.get("versions", {})
                        version_data = None
                        if releases and version in releases:
                            version_data = releases[version]
                            if isinstance(version_data, list) and len(version_data) > 0:
                                version_data = version_data[0]
                        elif versions_map and version in versions_map:
                            version_data = versions_map[version]

                        if isinstance(version_data, dict):
                            digests = version_data.get("digests", {})
                            sha = (
                                digests.get("sha256")
                                or digests.get("sha1")
                                or digests.get("md5")
                                or version_data.get("sha256")
                                or version_data.get("sha1")
                                or version_data.get("hash")
                                or "Unknown"
                            )

                    if sha == "Unknown":
                        info = package_data.get("info", {})
                        if isinstance(info, dict):
                            sha = (
                                info.get("sha256")
                                or info.get("sha1")
                                or info.get("hash")
                                or "Unknown"
                            )
                    if sha == "Unknown" and isinstance(result, dict):
                        doc_sha = result.get("sha")
                        if isinstance(doc_sha, str) and doc_sha.strip():
                            sha = doc_sha.strip()

                return license_str, package_url, sha, None

            # ------------------------------------------------------------------
            # Maven / Gradle
            # ------------------------------------------------------------------
            elif manager in ["maven", "gradle"]:
                fallback_url = _build_maven_url(name, version)
                result = get_package_by_name("maven", name)

                if not result:
                    logger.warning(f"Maven package not found in SBOM MongoDB: {name}")
                    return "-", fallback_url, "Unknown", None

                package_data = result.get("object") if isinstance(result, dict) and "object" in result else result

                if isinstance(package_data, dict):
                    package_data = dict(package_data)
                    nested_obj = package_data.get("object")
                    if isinstance(nested_obj, dict) and not package_data.get("licenses"):
                        if nested_obj.get("licenses"):
                            package_data["licenses"] = nested_obj["licenses"]
                    if isinstance(result, dict):
                        for key in ("licenses", "license", "license_expression"):
                            root_val = result.get(key)
                            if root_val in (None, "", []):
                                continue
                            if key == "licenses" and package_data.get("licenses"):
                                continue
                            if key != "licenses" and package_data.get(key):
                                continue
                            package_data[key] = root_val

                group_id = None
                artifact_id = None
                if isinstance(package_data, dict):
                    group_id = package_data.get("g") or package_data.get("groupId")
                    artifact_id = package_data.get("a") or package_data.get("artifactId")

                if not group_id or not artifact_id:
                    if ":" in name:
                        parts = name.split(":", 1)
                        group_id = parts[0]
                        artifact_id = parts[1]
                    else:
                        artifact_id = name
                        group_id = "unknown"

                # packageURL: always the official, version-specific registry page.
                if group_id and artifact_id and group_id != "unknown":
                    package_url = _build_maven_url(f"{group_id}:{artifact_id}", version)
                else:
                    package_url = fallback_url

                licenses: List[str] = []
                if isinstance(package_data, dict):
                    licenses = self._maven_mongo_license_names(package_data, result)

                if not licenses and isinstance(package_data, dict):
                    licenses = []
                    if "license" in package_data:
                        lic_val = package_data["license"]
                        if isinstance(lic_val, list):
                            licenses = [str(l).strip() for l in lic_val if l]
                        elif isinstance(lic_val, str):
                            licenses = [lic_val.strip()]
                        elif isinstance(lic_val, dict):
                            lic_name = (
                                lic_val.get("name")
                                or lic_val.get("type")
                                or lic_val.get("license")
                            )
                            if lic_name:
                                licenses = [str(lic_name).strip()]

                    if not licenses:
                        license_expr = package_data.get("license_expression")
                        if license_expr:
                            licenses = [str(license_expr).strip()]

                    if not licenses:
                        raw_licenses = package_data.get("licenses", [])
                        if isinstance(raw_licenses, str):
                            if raw_licenses.strip():
                                licenses = [raw_licenses.strip()]
                        elif isinstance(raw_licenses, list):
                            for lic in raw_licenses:
                                if isinstance(lic, dict):
                                    lic_name = (
                                        lic.get("name")
                                        or lic.get("type")
                                        or lic.get("license")
                                    )
                                    if lic_name:
                                        licenses.append(str(lic_name).strip())
                                elif isinstance(lic, str):
                                    licenses.append(lic.strip())
                        elif isinstance(raw_licenses, dict):
                            lic_name = (
                                raw_licenses.get("name")
                                or raw_licenses.get("type")
                                or raw_licenses.get("license")
                            )
                            if lic_name:
                                licenses = [str(lic_name).strip()]

                    if not licenses:
                        info = package_data.get("info", {})
                        if isinstance(info, dict) and "license" in info:
                            lic_val = info["license"]
                            if isinstance(lic_val, list):
                                licenses = [str(l).strip() for l in lic_val if l]
                            elif isinstance(lic_val, str):
                                licenses = [lic_val.strip()]
                            elif isinstance(lic_val, dict):
                                lic_name = (
                                    lic_val.get("name")
                                    or lic_val.get("type")
                                    or lic_val.get("license")
                                )
                                if lic_name:
                                    licenses.append(str(lic_name).strip())

                    if not licenses:
                        pom = package_data.get("pom", {})
                        if isinstance(pom, dict):
                            for lic in pom.get("licenses", []):
                                if isinstance(lic, dict):
                                    lic_name = (
                                        lic.get("name")
                                        or lic.get("type")
                                        or lic.get("license")
                                    )
                                    if lic_name:
                                        licenses.append(str(lic_name).strip())
                                elif isinstance(lic, str):
                                    licenses.append(lic.strip())

                cleaned_licenses = []
                for lic in licenses:
                    if lic and not self._is_empty_license(lic):
                        if "\n" in lic:
                            lic = lic.split("\n")[0].strip()
                        lic = lic[:50]
                        cleaned_licenses.append(lic)

                # Use "-" when no valid license found
                license_str = cleaned_licenses[0] if cleaned_licenses else "-"

                sha = "Unknown"
                if isinstance(package_data, dict):
                    sha = (
                        package_data.get("sha")
                        or package_data.get("sha256")
                        or package_data.get("sha1")
                        or package_data.get("hash")
                        or "Unknown"
                    )

                    if version and sha == "Unknown":
                        releases = package_data.get("releases", {})
                        versions_map = package_data.get("versions", {})
                        version_data = None
                        if releases and version in releases:
                            version_data = releases[version]
                            if isinstance(version_data, list) and len(version_data) > 0:
                                version_data = version_data[0]
                        elif versions_map and version in versions_map:
                            version_data = versions_map[version]

                        if isinstance(version_data, dict):
                            digests = version_data.get("digests", {})
                            sha = (
                                digests.get("sha256")
                                or digests.get("sha1")
                                or digests.get("md5")
                                or version_data.get("sha256")
                                or version_data.get("sha1")
                                or version_data.get("hash")
                                or "Unknown"
                            )

                    if sha == "Unknown":
                        info = package_data.get("info", {})
                        if isinstance(info, dict):
                            sha = (
                                info.get("sha256")
                                or info.get("sha1")
                                or info.get("hash")
                                or "Unknown"
                            )

                if sha == "Unknown" and isinstance(result, dict):
                    doc_sha = result.get("sha")
                    if isinstance(doc_sha, str) and doc_sha.strip():
                        sha = doc_sha.strip()

                return license_str, package_url, sha, None

        except Exception as e:
            logger.error(f"Error getting license for {manager}/{name}: {e}", exc_info=True)

        # Final fallback: return "-" and build the best URL we can
        fallback_url = "Unknown"
        if manager == "pypi":
            fallback_url = _build_pypi_url(name, version)
        elif manager == "npm":
            fallback_url = _build_npm_url(name, version.lstrip("^") if version else None)
        elif manager == "go":
            fallback_url = _build_go_url(name, version)
        elif manager in ("maven", "gradle"):
            fallback_url = _build_maven_url(name, version)

        return "-", fallback_url, "Unknown", None

    # ---------------------------------------------------------------------------
    # Dependency parsers
    # ---------------------------------------------------------------------------

    def _parse_requirements_txt_line(self, line: str) -> Optional[Tuple[str, Optional[str]]]:
        line = line.strip()
        if not line or line.startswith("#"):
            return None
        lower = line.lower()
        if lower.startswith(("-r ", "--requirement ", "-c ", "--constraint ")):
            return None
        if lower.startswith(("-e ", "--editable ")):
            return None
        if lower.startswith("--"):
            return None
        if " #" in line:
            line = line.split(" #", 1)[0].rstrip()
        if " @ " in line:
            line = line.split(" @ ", 1)[0].strip()
        m = re.match(
            r"^([a-zA-Z0-9][a-zA-Z0-9._-]*)(?:\[[^\]]+])?\s*(.*)$",
            line,
        )
        if not m:
            return None
        name = m.group(1)
        rest = (m.group(2) or "").strip()
        if not rest:
            return name, None
        if ";" in rest:
            rest = rest.split(";", 1)[0].strip()
        if not rest:
            return name, None
        pin = re.search(r"==\s*([^\s,]+)", rest)
        if pin:
            return name, pin.group(1).strip()
        ge = re.search(r">=\s*([^\s,]+)", rest)
        if ge:
            return name, ge.group(1).strip()
        le = re.search(r"<=\s*([^\s,]+)", rest)
        if le:
            return name, le.group(1).strip()
        gt = re.search(r">\s*([^\s,]+)", rest)
        if gt:
            return name, gt.group(1).strip()
        lt = re.search(r"<\s*([^\s,]+)", rest)
        if lt:
            return name, lt.group(1).strip()
        comp = re.search(r"~=\s*([^\s,]+)", rest)
        if comp:
            return name, comp.group(1).strip()
        return name, None

    def _make_pypi_dependency(self, name: str, version: Optional[str], path: str) -> Dict[str, Any]:
        license, package_url, sha, mongo_version = self._get_license(name, "pypi", version)
        version_info = version if version is not None else (mongo_version if mongo_version else "unspecified")
        return {
            "moduleName": name,
            "versionInfo": version_info,
            "sha": sha,
            "sourceLocation": path,
            "packageURL": package_url,
            "packageManager": "pypi",
            "licenseConcluded": license,
            # requirements.txt/Pipfile/pyproject.toml can only ever declare
            # direct deps - lock-file readers overwrite this with the real
            # direct/transitive split when they call this helper.
            "dependency_type": "direct",
        }

    def _read_requirements_txt(self, path: str) -> List[Dict[str, Any]]:
        dependencies = []
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                parsed = self._parse_requirements_txt_line(line)
                if not parsed:
                    continue
                name, version = parsed
                dependencies.append(self._make_pypi_dependency(name, version, path))
        return dependencies

    def _read_pipfile(self, path: str) -> List[Dict[str, Any]]:
        """Pipfile is TOML: [packages] runtime deps, [dev-packages] dev-only."""
        dependencies = []
        with open(path, "rb") as f:
            data = tomllib.load(f)
        for section in ("packages", "dev-packages"):
            for name, spec in (data.get(section) or {}).items():
                if isinstance(spec, dict):
                    version = spec.get("version")
                else:
                    version = str(spec) if spec else None
                if version in ("*", ""):
                    version = None
                if version and version[0] in "=<>!~^":
                    version = re.sub(r"^[=<>!~^\s]+", "", version).strip() or None
                dependencies.append(self._make_pypi_dependency(name, version, path))
        return dependencies

    def _read_pyproject_toml(self, path: str) -> List[Dict[str, Any]]:
        """pyproject.toml is TOML: [project] dependencies, [tool.poetry.dependencies] deps."""
        dependencies = []
        with open(path, "rb") as f:
            data = tomllib.load(f)

        for req in ((data.get("project") or {}).get("dependencies") or []):
            parsed = self._parse_requirements_txt_line(str(req))
            if parsed:
                name, version = parsed
                dependencies.append(self._make_pypi_dependency(name, version, path))

        poetry_deps = (
            (data.get("tool") or {}).get("poetry") or {}
        ).get("dependencies") or {}
        for name, spec in poetry_deps.items():
            if name.lower() == "python":
                continue  # not a package, this key pins the interpreter version
            if isinstance(spec, dict):
                version = spec.get("version")
            else:
                version = str(spec) if spec else None
            if version in ("*", ""):
                version = None
            if version and version[0] in "=<>!~^":
                version = re.sub(r"^[=<>!~^\s]+", "", version).strip() or None
            dependencies.append(self._make_pypi_dependency(name, version, path))

        return dependencies

    def _read_pipfile_lock(self, path: str) -> List[Dict[str, Any]]:
        """Reads Pipfile.lock's "default" and "develop" sections for exact
        resolved versions. cvedb-fetcher has no Pipfile.lock parser at all -
        every pypi dependency it emits defaults to "direct" - so this stays
        "direct" too rather than guessing at a transitive split cvedb-fetcher
        doesn't make."""
        dependencies = []
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            data = json.load(f)
        for section in ("default", "develop"):
            for name, spec in (data.get(section) or {}).items():
                version = (spec.get("version") or "").lstrip("=") or None
                dependencies.append(self._make_pypi_dependency(name, version, path))
        return dependencies

    def _read_poetry_lock(self, path: str) -> List[Dict[str, Any]]:
        """Reads poetry.lock's [[package]] array for exact resolved versions.
        Same "direct" rationale as _read_pipfile_lock - cvedb-fetcher has no
        poetry.lock parser either."""
        dependencies = []
        with open(path, "rb") as f:
            data = tomllib.load(f)
        for pkg in data.get("package") or []:
            name = pkg.get("name")
            if not name:
                continue
            dependencies.append(self._make_pypi_dependency(name, pkg.get("version"), path))
        return dependencies

    def _read_python_dependencies(self, file_map: Dict[str, List[str]], repo_path: str) -> List[Dict[str, Any]]:
        dependencies = []
        py_files = file_map.get("python", [])

        def paths_by_dir(basename: str) -> Dict[str, str]:
            return {
                os.path.dirname(p): p
                for p in py_files
                if os.path.basename(p).lower() == basename
            }

        pipfiles = paths_by_dir("pipfile")
        pipfile_locks = paths_by_dir("pipfile.lock")
        pyprojects = paths_by_dir("pyproject.toml")
        poetry_locks = paths_by_dir("poetry.lock")

        # Dirs already covered by a lock file - skip the fallback reader below.
        lock_handled_dirs: Set[str] = set()

        for dirpath, lock_path in pipfile_locks.items():
            pipfile_path = pipfiles.get(dirpath)
            if not pipfile_path:
                continue
            try:
                dependencies.extend(self._read_pipfile_lock(lock_path))
                lock_handled_dirs.add(dirpath)
            except Exception as e:
                logger.warning(f"Error reading Pipfile.lock dependencies from {lock_path}: {e}")

        for dirpath, lock_path in poetry_locks.items():
            pyproject_path = pyprojects.get(dirpath)
            if not pyproject_path:
                continue
            try:
                dependencies.extend(self._read_poetry_lock(lock_path))
                lock_handled_dirs.add(dirpath)
            except Exception as e:
                logger.warning(f"Error reading poetry.lock dependencies from {lock_path}: {e}")

        readers = {
            "requirements.txt": self._read_requirements_txt,
            "pipfile": self._read_pipfile,
            "pyproject.toml": self._read_pyproject_toml,
        }
        for path in py_files:
            basename = os.path.basename(path).lower()
            if basename in ("pipfile", "pyproject.toml") and os.path.dirname(path) in lock_handled_dirs:
                continue
            reader = readers.get(basename)
            if not reader:
                continue
            try:
                dependencies.extend(reader(path))
            except Exception as e:
                logger.warning(f"Error reading Python dependencies from {path}: {e}")
                continue
        return dependencies

    def _read_java_maven_dependencies(self, file_map: Dict[str, List[str]], repo_path: str) -> List[Dict[str, Any]]:
        dependencies = []
        for path in file_map.get("java_maven", []):
            try:
                tree = ET.parse(path)
                root = tree.getroot()
                ns = {"m": "http://maven.apache.org/POM/4.0.0"}

                # --- Step 1: collect all <properties> for placeholder resolution ---
                properties: Dict[str, str] = {}
                props_el = root.find("m:properties", ns)
                if props_el is not None:
                    for prop in props_el:
                        tag = prop.tag.split("}")[-1] if "}" in prop.tag else prop.tag
                        if prop.text and prop.text.strip():
                            properties[tag] = prop.text.strip()

                project_version_el = root.find("m:version", ns)
                if project_version_el is not None and project_version_el.text:
                    properties.setdefault("project.version", project_version_el.text.strip())
                    properties.setdefault("pom.version", project_version_el.text.strip())

                def resolve(value: Optional[str], max_passes: int = 5) -> Optional[str]:
                    if not value:
                        return value
                    for _ in range(max_passes):
                        new_value = re.sub(
                            r"\$\{([^}]+)\}",
                            lambda m: properties.get(m.group(1), m.group(0)),
                            value,
                        )
                        if new_value == value:
                            break
                        value = new_value
                    return value

                # --- Step 2: parse dependencies and resolve versions ---
                for dep in root.findall(".//m:dependency", ns):
                    group = dep.find("m:groupId", ns)
                    artifact = dep.find("m:artifactId", ns)
                    version_el = dep.find("m:version", ns)

                    if group is None or artifact is None:
                        continue

                    raw_version = version_el.text if version_el is not None else None
                    resolved_version = resolve(raw_version)

                    # Skip if version is still an unresolved placeholder
                    if resolved_version and re.match(r"^\$\{", resolved_version):
                        logger.debug(
                            f"Skipping unresolved Maven version placeholder '{resolved_version}' "
                            f"for {group.text}:{artifact.text} in {path}"
                        )
                        resolved_version = None

                    name = f"{group.text}:{artifact.text}"


                    # FIX: If no version from POM, try fetching from MongoDB first

                    # If no version from POM, try fetching from MongoDB first

                    if not resolved_version:
                        mongo_version = self._get_maven_version_from_mongo(name)
                        if mongo_version:
                            resolved_version = mongo_version
                            logger.debug(f"Resolved version for {name} from MongoDB: {resolved_version}")

                    license, package_url, sha, _ = self._get_license(name, "maven", resolved_version)

                    if not license or license.strip().lower() in {"unknown", "none", "null", "-", ""}:
                        license = "-"


                    dependencies.append({
                        "moduleName": name,
                        "versionInfo": resolved_version,
                        "sha": sha,
                        "sourceLocation": path,
                        "packageURL": package_url,
                        "packageManager": "maven",
                        "licenseConcluded": license,
                        # pom.xml can only ever declare direct deps - Maven has no lock format.
                        "dependency_type": "direct",
                    })

            except Exception as e:
                logger.warning(f"Error reading Maven dependencies from {path}: {e}")
                continue
        return dependencies

    def _get_maven_version_from_mongo(self, name: str) -> Optional[str]:
        """
        Fetch the latest/stored version for a Maven package from MongoDB.
        Returns version string if found, else None.
        """
        if self._sbom_count_only:
            return None
        try:
            result = get_package_by_name("maven", name)
            if not result:
                return None

            package_data = (
                result.get("object")
                if isinstance(result, dict) and "object" in result
                else result
            )

            if not isinstance(package_data, dict):
                return None

            # Try common version fields in order of preference
            for field in ("latestVersion", "latest_version", "version", "v"):
                val = package_data.get(field)
                if val and isinstance(val, str) and val.strip():
                    return val.strip()

            # Try nested object
            nested = package_data.get("object")
            if isinstance(nested, dict):
                for field in ("latestVersion", "latest_version", "version", "v"):
                    val = nested.get(field)
                    if val and isinstance(val, str) and val.strip():
                        return val.strip()

            # Try versions map — pick the last key (usually latest)
            versions_map = package_data.get("versions") or package_data.get("releases")
            if isinstance(versions_map, dict) and versions_map:
                return list(versions_map.keys())[-1]

        except Exception as e:
            logger.warning(f"Error fetching Maven version from MongoDB for {name}: {e}")

        return None

    def _read_build_gradle_file(self, path: str) -> List[Dict[str, Any]]:
        dependencies = []
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
               
                match = re.search(
                    r"(\w+)\s*\(?\s*['\"]([\w\.\-]+):([\w\.\-]+):([\w\.\-]+)['\"]",
                    line
                )
                if match:
                    name = f"{match.group(2)}:{match.group(3)}"
                    version = match.group(4)
                    license, package_url, sha, _ = self._get_license(name, "gradle", version)
                    dependencies.append({
                        "moduleName": name,
                        "versionInfo": version,
                        "sha": sha,
                        "sourceLocation": path,
                        "packageURL": package_url,
                        "packageManager": "gradle",
                        "licenseConcluded": license,
                        # build.gradle(.kts) can only ever declare direct deps -
                        # _read_gradle_lockfile overwrites this with the real
                        # split when a gradle.lockfile is present.
                        "dependency_type": "direct",
                    })
        return dependencies

    def _read_gradle_lockfile(self, path: str) -> List[Dict[str, Any]]:
        """gradle.lockfile is a flat "group:artifact:version=configs" list with
        no direct/transitive marker. cvedb-fetcher has no gradle.lockfile
        parser at all - its gradle dependencies always default to "direct" -
        so these do too, rather than guessing at a split cvedb-fetcher
        doesn't make."""
        dependencies = []
        seen: Set[Tuple[str, str]] = set()
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or line.startswith("empty="):
                    continue
                match = re.match(r"([\w\.\-]+):([\w\.\-]+):([\w\.\-]+)=", line)
                if not match:
                    continue
                group, artifact, version = match.groups()
                name = f"{group}:{artifact}"
                if (name, version) in seen:
                    continue  # same coordinate often repeats once per configuration
                seen.add((name, version))
                license, package_url, sha, _ = self._get_license(name, "gradle", version)
                dependencies.append({
                    "moduleName": name,
                    "versionInfo": version,
                    "sha": sha,
                    "sourceLocation": path,
                    "packageURL": package_url,
                    "packageManager": "gradle",
                    "licenseConcluded": license,
                    "dependency_type": "direct",
                })
        return dependencies

    def _read_java_gradle_dependencies(self, file_map: Dict[str, List[str]], repo_path: str) -> List[Dict[str, Any]]:
        dependencies = []
        gradle_files = file_map.get("java_gradle", [])
        build_files = [p for p in gradle_files if os.path.basename(p).lower() != "gradle.lockfile"]
        lockfiles_by_dir = {
            os.path.dirname(p): p
            for p in gradle_files
            if os.path.basename(p).lower() == "gradle.lockfile"
        }

        for path in build_files:
            try:
                lockfile_path = lockfiles_by_dir.get(os.path.dirname(path))
                if lockfile_path:
                    from_lock = self._read_gradle_lockfile(lockfile_path)
                    if from_lock:
                        dependencies.extend(from_lock)
                        continue
                dependencies.extend(self._read_build_gradle_file(path))
            except Exception as e:
                logger.warning(f"Error reading Gradle dependencies from {path}: {e}")
                continue
        return dependencies

    def _read_package_json(self, path: str) -> List[Dict[str, Any]]:
        """package.json only lists what this project declares directly -
        devDependencies are dev-only, dependencies/optionalDependencies are
        direct runtime deps (mirrors cvedb-fetcher's parse_package_json)."""
        dependencies = []
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            data = json.load(f)
        npm_sections = (
            ("dependencies", "production", "direct"),
            ("devDependencies", "development", "dev"),
            ("optionalDependencies", "optional", "direct"),
            ("dependencies", "production", "direct"),
            ("devDependencies", "development", "dev"),
            ("optionalDependencies", "optional", "direct"),
        )
        for section_name, scope_type, dep_type in npm_sections:
            deps = data.get(section_name, {})
            if not isinstance(deps, dict):
                continue
            for name, version in deps.items():
                license, package_url, sha, _ = self._get_license(name, "npm", version)
                version_info = "" if version is None else str(version).lstrip("^")
                dependencies.append({
                    "moduleName": name,
                    "versionInfo": version_info,
                    "sha": sha,
                    "sourceLocation": path,
                    "packageURL": package_url,
                    "packageManager": "npm",
                    "licenseConcluded": license,
                    "dependencyType": scope_type,
                    "dependency_type": dep_type,
                })
        return dependencies

    def _read_package_lock_json(self, path: str) -> List[Dict[str, Any]]:
        """lockfileVersion 2/3's flat "packages" map. Root "" mirrors
        package.json's direct deps. A package nested more than one
        "node_modules/" level deep is always transitive regardless of name
        collisions with a root dep; a top-level (non-nested) entry flagged
        "dev": true is a dev dependency; everything else not in the root's
        declared sections is transitive. Mirrors cvedb-fetcher's
        parse_package_lock_json. Older lockfileVersion 1 (no "packages" key)
        isn't handled - caller falls back to package.json-only parsing."""
        dependencies = []
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            data = json.load(f)

        packages = data.get("packages")
        if not isinstance(packages, dict):
            return dependencies

        root = packages.get("", {})
        direct_names = set()
        for section in ("dependencies", "devDependencies", "optionalDependencies"):
            direct_names.update((root.get(section) or {}).keys())

        for pkg_path, pkg_info in packages.items():
            if pkg_path == "" or not isinstance(pkg_info, dict):
                continue
            name = pkg_path.rsplit("node_modules/", 1)[-1]
            if not name:
                continue
            version = pkg_info.get("version")
            is_dev = bool(pkg_info.get("dev"))
            is_nested = pkg_path.count("node_modules/") > 1
            is_transitive = is_nested or (name not in direct_names and not is_dev)
            if is_dev and not is_nested:
                dep_type = "dev"
            elif is_transitive:
                dep_type = "transitive"
            else:
                dep_type = "direct"
            scope_type = "development" if is_dev else "production"
            license, package_url, sha, _ = self._get_license(name, "npm", version)
            dependencies.append({
                "moduleName": name,
                "versionInfo": version or "",
                "sha": sha,
                "sourceLocation": path,
                "packageURL": package_url,
                "packageManager": "npm",
                "licenseConcluded": license,
                "dependencyType": scope_type,
                "dependency_type": dep_type,
            })
        return dependencies

    def _read_javascript_dependencies(self, file_map: Dict[str, List[str]], repo_path: str) -> List[Dict[str, Any]]:
        dependencies = []
        js_files = file_map.get("javascript", [])
        lockfiles_by_dir = {
            os.path.dirname(p): p
            for p in js_files
            if os.path.basename(p).lower() == "package-lock.json"
        }

        for path in js_files:
            if os.path.basename(path).lower() != "package.json":
                continue
            try:
                lockfile_path = lockfiles_by_dir.get(os.path.dirname(path))
                if lockfile_path:
                    from_lock = self._read_package_lock_json(lockfile_path)
                    if from_lock:
                        dependencies.extend(from_lock)
                        continue
                dependencies.extend(self._read_package_json(path))
            except Exception as e:
                logger.warning(f"Error reading JavaScript dependencies from {path}: {e}")
                continue
        return dependencies

    def _read_go_dependencies(self, file_map: Dict[str, List[str]], repo_path: str) -> List[Dict[str, Any]]:
        dependencies = []
        for path in file_map.get("go", []):
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    in_require_block = False
                    for line in f:
                        line = line.strip()

                        if not line or line.startswith("//"):
                            continue
                        if line.startswith("module "):
                            continue
                        if line.startswith("go "):
                            continue
                        if any(line.startswith(d + " ") for d in ["replace", "exclude", "retract"]):
                            continue

                        if line.startswith("require ("):
                            in_require_block = True
                            continue

                        if in_require_block:
                            if line == ")":
                                in_require_block = False
                                continue
                            # cvedb-fetcher's parse_go_mod does not read the
                            # "// indirect" marker either - every go.mod entry
                            # defaults to "direct" there.
                            match = re.match(
                                r"([\w\.\-/]+(?:\s+=>\s+[\w\.\-/]+)?)\s+(v?[\d\.\w\-]+)(?:\s+//\s*(.*))?",
                                line
                            )
                            if match:
                                name_part, version, _comment = match.groups()
                                name = name_part.split(" => ")[-1].strip() if " => " in name_part else name_part.strip()
                                if version.startswith("v"):
                                    version = version[1:]
                                license, package_url, sha, _ = self._get_license(name, "go", version)
                                dependencies.append({
                                    "moduleName": name,
                                    "versionInfo": version,
                                    "sha": sha,
                                    "sourceLocation": path,
                                    "packageURL": package_url,
                                    "packageManager": "go",
                                    "licenseConcluded": license,
                                    "dependency_type": "direct",
                                })
                            continue

                        match = re.match(
                            r"require\s+([\w\.\-/]+(?:\s+=>\s+[\w\.\-/]+)?)\s+(v?[\d\.\w\-]+)(?:\s+//\s*(.*))?",
                            line
                        )
                        if match:
                            name_part, version, _comment = match.groups()
                            name = name_part.split(" => ")[-1].strip() if " => " in name_part else name_part.strip()
                            if version.startswith("v"):
                                version = version[1:]
                            license, package_url, sha, _ = self._get_license(name, "go", version)
                            dependencies.append({
                                "moduleName": name,
                                "versionInfo": version,
                                "sha": sha,
                                "sourceLocation": path,
                                "packageURL": package_url,
                                "packageManager": "go",
                                "licenseConcluded": license,
                                "dependency_type": "direct",
                            })
            except Exception as e:
                logger.warning(f"Error reading Go dependencies from {path}: {e}", exc_info=True)
                continue
        return dependencies

    # ---------------------------------------------------------------------------
    # Aggregation
    # ---------------------------------------------------------------------------

    def _collect_dependencies(self, file_map: Dict[str, List[str]], repo_path: str) -> List[Dict[str, Any]]:
        all_dependencies = []

        sbom_artifacts = file_map.get("sbom_artifacts", [])
        if sbom_artifacts:
            all_dependencies.extend(self._read_sbom_artifact_dependencies(sbom_artifacts))

        all_dependencies.extend(self._read_python_dependencies(file_map, repo_path))
        all_dependencies.extend(self._read_java_maven_dependencies(file_map, repo_path))
        all_dependencies.extend(self._read_java_gradle_dependencies(file_map, repo_path))
        all_dependencies.extend(self._read_javascript_dependencies(file_map, repo_path))
        all_dependencies.extend(self._read_go_dependencies(file_map, repo_path))
        return all_dependencies

    def _extract_all_dependencies(self, file_map: Dict[str, List[str]], repo_path: str) -> List[Dict[str, Any]]:
        """Runs the readers twice: a throwaway dry-run pass (Mongo calls
        short-circuited via _sbom_count_only) purely to learn how many
        packages the real pass will query, so _log_sbom_progress can report
        one line at ~50% and one at 100% instead of one per package."""
        self._sbom_count_only = True
        self._sbom_progress_current = 0
        try:
            self._collect_dependencies(file_map, repo_path)
        finally:
            self._sbom_count_only = False

        self._sbom_progress_total = self._sbom_progress_current
        self._sbom_progress_current = 0
        self._sbom_progress_half_logged = False
        self._sbom_progress_complete_logged = False

        return self._collect_dependencies(file_map, repo_path)

    # ------------------------------------------------------------------
    # SBOM-format generation (SPDX 2.3 + CycloneDX 1.5)
    # ------------------------------------------------------------------

    # Maps internal packageManager keys → SPDX/CycloneDX document ecosystem keys
    _ECO_KEY: Dict[str, str] = {
        "pypi": "python",
        "maven": "java-maven",
        "gradle": "java-gradle",
        "npm": "javascript",
        "go": "go",
    }

    # Maps internal packageManager keys → purl ecosystem identifier
    _PURL_ECO: Dict[str, str] = {
        "pypi": "pypi",
        "maven": "maven",
        "gradle": "maven",
        "npm": "npm",
        "go": "golang",
    }

    def _build_spdx_document(
        self,
        enriched_deps: List[Dict[str, Any]],
        scan_id: str,
    ) -> Dict[str, Any]:
        packages = []
        for dep in enriched_deps:
            spdx_stack = dep.get("stacks", {}).get("spdx", {})
            raw_license = dep.get("license")
            spdx_license = (
                raw_license
                if raw_license and not self._is_empty_license(raw_license)
                else "NOASSERTION"
            )
            pkg: Dict[str, Any] = {
                "SPDXID": spdx_stack.get("id", f"SPDXRef-{dep.get('name', 'unknown')}"),
                "name": dep.get("name") or "Unknown",
                "downloadLocation": spdx_stack.get("download_location", "NOASSERTION"),
                "filesAnalyzed": spdx_stack.get("files_analyzed", False),
                "licenseConcluded": spdx_license,
            }
            if dep.get("version"):
                pkg["versionInfo"] = dep["version"]
            if dep.get("purl"):
                pkg["externalRefs"] = [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": dep["purl"],
                    }
                ]
            packages.append(pkg)

        return {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": f"sbom-{scan_id}",
            "documentNamespace": f"https://zyloch.io/sbom/{scan_id}",
            "packages": packages,
        }

    def _build_cyclonedx_document(
        self,
        enriched_deps: List[Dict[str, Any]],
        scan_id: str,
    ) -> Dict[str, Any]:
        components = []
        for dep in enriched_deps:
            cdx_stack = dep.get("stacks", {}).get("cyclonedx", {})
            comp: Dict[str, Any] = {
                "type": cdx_stack.get("type", "library"),
                "bom-ref": cdx_stack.get("bom_ref", ""),
                "name": dep.get("name") or "Unknown",
            }
            if dep.get("version"):
                comp["version"] = dep["version"]
            if dep.get("purl"):
                comp["purl"] = dep["purl"]
            license_val = dep.get("license")
            if license_val and not self._is_empty_license(license_val):
                comp["licenses"] = [{"license": {"id": license_val}}]
            components.append(comp)

        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "version": 1,
            "serialNumber": f"urn:uuid:{scan_id}",
            "components": components,
        }

    def _write_sbom_files(
        self,
        enriched_deps: List[Dict[str, Any]],
        scan_id: str,
        output_dir: str,
    ) -> None:
        os.makedirs(output_dir, exist_ok=True)

        spdx_doc = self._build_spdx_document(enriched_deps, scan_id)
        spdx_path = os.path.join(output_dir, "spdx.json")
        with open(spdx_path, "w", encoding="utf-8") as f:
            json.dump(spdx_doc, f, indent=2)
        logger.info("SPDX document written to %s", spdx_path)

        cdx_doc = self._build_cyclonedx_document(enriched_deps, scan_id)
        cdx_path = os.path.join(output_dir, "cyclonedx.json")
        with open(cdx_path, "w", encoding="utf-8") as f:
            json.dump(cdx_doc, f, indent=2)
        logger.info("CycloneDX document written to %s", cdx_path)

    def _build_sbom_formatted_output(
        self,
        dependencies: List[Dict[str, Any]],
        repo_path: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Enrich each dependency with SPDX and CycloneDX format-specific fields
        nested under stacks{}.

        Common fields (name, version, ecosystem, purl, source_file, sha, license)
        stay at the top level.  SPDX-unique and CycloneDX-unique fields — including
        per-ecosystem document headers — are embedded inside stacks.spdx and
        stacks.cyclonedx respectively so each entry is self-contained.
        """
        enriched: List[Dict[str, Any]] = []

        try:
            vuln_map = bulk_find_vulnerabilities(dependencies, repo_path)
        except Exception as exc:
            logger.warning("CVE lookup failed, continuing without vulnerabilities: %s", exc)
            vuln_map = {}

        for idx, dep in enumerate(dependencies):
            name        = dep.get("moduleName")
            version     = dep.get("versionInfo")
            eco         = dep.get("packageManager")
            license_val = dep.get("licenseConcluded")
            sha         = dep.get("sha")
            source_file = dep.get("sourceLocation")
            vulnerabilities = vuln_map.get((name.lower(), eco), []) if name and eco else []

            purl_eco = self._PURL_ECO.get(eco, eco) if eco else "unknown"
            # Go module versions are always "v"-prefixed (e.g. v1.33.6) - zyloch
            # strips that prefix when parsing go.mod, so it has to be added back
            # here to match Go's own versioning convention and pkg.go.dev URLs.
            purl_version = version
            if purl_version and eco == "go" and not str(purl_version).startswith("v"):
                purl_version = f"v{purl_version}"
            purl = (
                f"pkg:{purl_eco}/{(name or '').lower()}@{purl_version}"
                if purl_version
                else f"pkg:{purl_eco}/{(name or '').lower()}"
            )

            bom_hash1 = abs(hash(f"{name}{version}")) % (10 ** 16)
            bom_hash2 = abs(hash(f"{eco}{source_file}")) % (10 ** 16)

            # Resolve download_location: use real registry URL when available
            pkg_url = dep.get("packageURL")
            if pkg_url and isinstance(pkg_url, str) and pkg_url not in {"Unknown", ""}:
                download_location = pkg_url
            else:
                # Build from ecosystem as a best-effort fallback
                if eco == "pypi" and name:
                    download_location = _build_pypi_url(name, version)
                elif eco == "npm" and name:
                    download_location = _build_npm_url(name, version.lstrip("^") if version else None)
                elif eco == "go" and name:
                    download_location = _build_go_url(name, version)
                elif eco in ("maven", "gradle") and name:
                    download_location = _build_maven_url(name, version)
                else:
                    download_location = "NOASSERTION"

            # files_analyzed defaults to False (lockfile scans do not analyze package files)
            spdx_stack: Dict[str, Any] = {
                "id": f"SPDXRef-Package-{idx}-{name}",
                "download_location": download_location,
                "files_analyzed": False,
            }

            # Package-level CycloneDX-unique fields only
            cdx_stack: Dict[str, Any] = {
                "bom_ref": f"BomRef.{bom_hash1}.{bom_hash2}",
                "type": dep.get("componentType") or "library",
            }

            enriched.append({
                "name": name,
                "version": version,
                "ecosystem": eco,
                "source_file": source_file,
                "purl": purl,
                "license": license_val,
                "sha": sha,
                "stacks": {
                    "spdx": spdx_stack,
                    "cyclonedx": cdx_stack,
                },
                # null unless a lock file gave a real direct/transitive signal.
                "dependency_type": dep.get("dependency_type"),
                "vulnerabilities": vulnerabilities,
            })

        return enriched

    def _calculate_statistics(self, dependencies: List[Dict[str, Any]]) -> Dict[str, Any]:
        total_packages = len(dependencies)

        package_managers = set()
        for dep in dependencies:
            package_managers.add(dep.get("packageManager", "unknown"))
        total_package_managers = len(package_managers)

        licenses = set()
        unknown_licenses_count = 0
        for dep in dependencies:
            license = dep.get("licenseConcluded", "-")
            if isinstance(license, list):
                license = license[0] if license else "-"
            if license and not self._is_empty_license(license) and license != "-":
                licenses.add(str(license))
            else:
                unknown_licenses_count += 1

        unique_license_types = len(licenses)
        legal_review_required = unknown_licenses_count > 0

        return {
            "total_packages": total_packages,
            "total_package_managers": total_package_managers,
            "unique_license_types": unique_license_types,
            "unknown_licenses_count": unknown_licenses_count,
            "legal_review_required": legal_review_required,
            "package_managers": list(package_managers),
            "licenses": list(licenses)
        }

    # LICENSE_POLICY_MAP.json's riskLevel has no "Critical" tier - License risk
    # tops out at "High" (e.g. GPL/AGPL, no declared license). "Variable" (custom/
    # negotiated enterprise licenses) has no clean equivalent, so it maps to MEDIUM.
    _LICENSE_RISK_SEVERITY = {
        "Low": ScanSeverity.LOW,
        "Medium": ScanSeverity.MEDIUM,
        "Variable": ScanSeverity.MEDIUM,
        "High": ScanSeverity.HIGH,
    }

    def _dependencies_to_findings(
        self,
        dependencies: List[Dict[str, Any]],
    ) -> List[ScanFinding]:
        findings = []
        for dep in dependencies:
            license = dep.get("licenseConcluded", "-")
            if isinstance(license, list):
                license = license[0] if license else "-"

            risk_level = get_license_risk_level(license if not self._is_empty_license(license) else None)
            severity = self._LICENSE_RISK_SEVERITY.get(risk_level, ScanSeverity.HIGH)

            license_display = "-" if not license or self._is_empty_license(license) else license

            description = (
                f"Package: {dep.get('moduleName', 'Unknown')} "
                f"v{dep.get('versionInfo', 'Unknown')} | "
                f"License: {license_display} | "
                f"Manager: {dep.get('packageManager', 'Unknown')}"
            )

            finding = ScanFinding(
                policy=f"sbom_{dep.get('packageManager', 'unknown')}",
                severity=severity,
                description=description,
                code=dep.get("sha", "N/A"),
                url=dep.get("packageURL", None),
                file=dep.get("sourceLocation", ""),
                line=None,
                match=dep.get("moduleName", "")
            )
            findings.append(finding)

        return findings


def scan_sbom(request: ScanRequest) -> ScanResponse:
    """Convenience function to run SBOM scan"""
    scanner = SBOMScanner()
    return scanner.scan(request)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="SBOM Scanner Microservice")
    parser.add_argument("--repo-path", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--scan-id", required=True)

    args = parser.parse_args()
    req = ScanRequest(repo_path=args.repo_path, output_dir=args.output_dir, scan_id=args.scan_id)
    response = scan_sbom(req)
    print(response.json())