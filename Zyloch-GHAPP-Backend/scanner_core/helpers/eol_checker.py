from __future__ import annotations

import json
import logging
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, asdict, field
from datetime import date, datetime
from typing import Any, Dict, List, Optional, Tuple, Union
from scanner_core.logging_config import get_scanner_logger
logger = get_scanner_logger()

EOL_PRODUCT_SLUGS = {
    "java": "oracle-jdk",
    "go": "go",
    "gradle_wrapper": "gradle",
    "maven_wrapper": "apache-maven",
    "npm": "nodejs",
    "python": "python",
    "terraform": "terraform",
}

# Terraform Registry public API base (kept for fallback only)
TF_REGISTRY_API_BASE = "https://registry.terraform.io/v1/providers"

# MongoDB collection names (must match script_eol.py)
COLLECTION_ENDOFLIFE = "eol_endoflife_products"
COLLECTION_TERRAFORM = "eol_terraform_providers"


# ========== Terraform cloud-provider classification ==========

_PROVIDER_SOURCE_TO_CLOUD: Dict[str, str] = {
    "hashicorp/aws":                    "AWS",
    "hashicorp/google":                 "GCP",
    "hashicorp/google-beta":            "GCP",
    "hashicorp/azurerm":                "Azure",
    "hashicorp/azuread":                "Azure",
    "hashicorp/azurestack":             "Azure",
    "hashicorp/kubernetes":             "Kubernetes",
    "hashicorp/helm":                   "Kubernetes",
    "hashicorp/vault":                  "HashiCorp Vault",
    "hashicorp/consul":                 "HashiCorp Consul",
    "hashicorp/nomad":                  "HashiCorp Nomad",
    "hashicorp/tfe":                    "Terraform Enterprise",
    "hashicorp/random":                 "HashiCorp",
    "hashicorp/null":                   "HashiCorp",
    "hashicorp/local":                  "HashiCorp",
    "hashicorp/template":               "HashiCorp",
    "hashicorp/time":                   "HashiCorp",
    "hashicorp/tls":                    "HashiCorp",
    "hashicorp/cloudinit":              "HashiCorp",
    "hashicorp/external":               "HashiCorp",
    "hashicorp/http":                   "HashiCorp",
    "hashicorp/archive":                "HashiCorp",
    "hashicorp/dns":                    "HashiCorp",
    "cloudflare/cloudflare":            "Cloudflare",
    "datadog/datadog":                  "Datadog",
    "grafana/grafana":                  "Grafana",
    "pagerduty/pagerduty":              "PagerDuty",
    "newrelic/newrelic":                "New Relic",
    "sumologic/sumologic":              "Sumo Logic",
    "splunk/splunk":                    "Splunk",
    "github/github":                    "GitHub",
    "integrations/github":              "GitHub",
    "gitlabhq/gitlab":                  "GitLab",
    "mongodb/mongodbatlas":             "MongoDB Atlas",
    "snowflake-labs/snowflake":         "Snowflake",
    "confluentinc/confluent":           "Confluent",
    "elastic/ec":                       "Elastic Cloud",
    "digitalocean/digitalocean":        "DigitalOcean",
    "linode/linode":                    "Linode",
    "vultr/vultr":                      "Vultr",
    "hetznercloud/hcloud":              "Hetzner Cloud",
    "oracle/oci":                       "OCI",
    "ibm-cloud/ibm":                    "IBM Cloud",
    "aliyun/alicloud":                  "Alibaba Cloud",
    "tencentcloudstack/tencentcloud":   "Tencent Cloud",
    "huaweicloud/huaweicloud":          "Huawei Cloud",
}


def _provider_tail_lookup_from_sources(
    source_to_cloud: Dict[str, str],
) -> Dict[str, str]:
    tail_map: Dict[str, str] = {}
    for src, label in source_to_cloud.items():
        tail = src.rsplit("/", 1)[-1]
        if tail not in tail_map:
            tail_map[tail] = label
    return tail_map


_PROVIDER_TAIL_TO_CLOUD: Dict[str, str] = _provider_tail_lookup_from_sources(
    _PROVIDER_SOURCE_TO_CLOUD
)

def classify_terraform_cloud_provider(
    provider_type_hint: Optional[str], source: Optional[str]
) -> str:
    def _norm(s: str) -> str:
        s = s.strip().lower()
        if s.startswith("registry.terraform.io/"):
            s = s[len("registry.terraform.io/"):]
        return s

    if source and source.strip():
        norm = _norm(source)
        if norm in _PROVIDER_SOURCE_TO_CLOUD:
            return _PROVIDER_SOURCE_TO_CLOUD[norm]
        tail = norm.rsplit("/", 1)[-1]
        if tail in _PROVIDER_TAIL_TO_CLOUD:
            return _PROVIDER_TAIL_TO_CLOUD[tail]

    if provider_type_hint and provider_type_hint.strip():
        name = provider_type_hint.strip().lower()
        if name in _PROVIDER_TAIL_TO_CLOUD:
            return _PROVIDER_TAIL_TO_CLOUD[name]
        for prefix in ("terraform-provider-", "provider-"):
            if name.startswith(prefix):
                stripped = name[len(prefix):]
                if stripped in _PROVIDER_TAIL_TO_CLOUD:
                    return _PROVIDER_TAIL_TO_CLOUD[stripped]

    return "Other"


# ========== MongoDB helpers ==========

def _get_mongo_db() -> Optional[Any]:
    """
    Return the SBOM/Intel MongoDB database object, or None if unavailable.
    Reuses the connection established by sbom_mongo_utils to avoid creating
    a second client.
    """
    try:
        from scanner_core.helpers.sbom_mongo_utils import get_sbom_database
        return get_sbom_database()
    except Exception as e:
        logger.debug(f"Could not obtain SBOM MongoDB handle: {e}")
        return None


def _mongo_fetch_endoflife(slug: str) -> Optional[List[dict]]:
    """
    Look up pre-cached endoflife.date releases from MongoDB.
    Collection: eol_endoflife_products  (unique index on 'slug').
    Returns the releases list, or None if not found.
    """
    db = _get_mongo_db()
    if db is None:
        logger.error("[EOL][MONGO] No DB handle — slug=%s", slug)
        return None
    try:
        doc = db[COLLECTION_ENDOFLIFE].find_one(
            {"slug": slug},
            {"releases": 1, "_id": 0},
        )
        if not doc:
            logger.debug("[EOL][MONGO] Miss — slug=%s", slug)
            return None
        releases = doc.get("releases")
        if not isinstance(releases, list):
            logger.warning(
                "[EOL][MONGO] Unexpected releases type — slug=%s type=%s",
                slug, type(releases).__name__,
            )
            return None
        if not releases:
            logger.warning("[EOL][MONGO] Empty releases list — slug=%s", slug)
            return None
        logger.debug("[EOL][MONGO] Hit — slug=%s releases=%d", slug, len(releases))
        return releases
    except Exception:
        logger.exception("[EOL][MONGO] Query failed — slug=%s", slug)
        return None
    
def _mongo_fetch_terraform_provider(namespace: str, provider_type: str) -> Optional[Dict[str, Any]]:
    """
    Look up pre-cached Terraform Registry info from MongoDB.
    Collection: eol_terraform_providers  (unique index on 'cache_key').
    Returns registry-info dict or None.
    """
    cache_key = f"{namespace}/{provider_type}".lower().strip()
    db = _get_mongo_db()
    if db is None:
        logger.debug("MongoDB unavailable; skipping TF cache lookup for %s", cache_key)
        return None
    try:
        col = db[COLLECTION_TERRAFORM]
        doc = col.find_one({"cache_key": cache_key}, {"_id": 0, "sha": 0, "fetched_at": 0})
        if doc:
            logger.debug("TF provider cache hit (mongo): %s", cache_key)
            # Normalise to the shape fetch_terraform_provider_registry_info() returned
            return {
                "latest_version":        doc.get("latest_version"),
                "published_at":          doc.get("published_at"),
                "versions":              doc.get("versions", []),
                "registry_address":      doc.get("registry_address", cache_key),
                "indexed_version_count": doc.get("indexed_version_count", 0),
                "latest_protocols":      doc.get("latest_protocols"),
            }
        logger.debug("TF provider cache miss (mongo): %s", cache_key)
        return None
    except Exception as e:
        logger.warning("Error reading TF provider from MongoDB (%s): %s", cache_key, e)
        return None


# ========== Terraform Registry API integration (live fallback) ==========

def _parse_provider_source(source: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
    if not source or not source.strip():
        return None, None
    s = source.strip().lower()
    if s.startswith("registry.terraform.io/"):
        s = s[len("registry.terraform.io/"):]
    parts = s.split("/")
    if len(parts) >= 2:
        return parts[-2], parts[-1]
    return None, None


def fetch_terraform_provider_registry_info(
    namespace: str, provider_type: str
) -> Optional[Dict[str, Any]]:
    """
    Return Terraform provider info.
    Priority: MongoDB cache → live Terraform Registry API.
    """
    # 1. Try MongoDB cache first
    cached = _mongo_fetch_terraform_provider(namespace, provider_type)
    if cached is not None:
        return cached

    # 2. Fall back to live API
    import requests
    url = f"{TF_REGISTRY_API_BASE}/{namespace}/{provider_type}/versions"
    headers = {
        "User-Agent": "repo-lang-version-scanner/1.1",
        "Accept": "application/json",
    }
    try:
        logger.debug("Fetching Terraform Registry info (live): %s", url)
        r = requests.get(url, headers=headers, timeout=30)
        if r.status_code == 404:
            return None
        r.raise_for_status()
        data = r.json()

        versions_raw = data.get("versions", [])
        if not versions_raw or not isinstance(versions_raw, list):
            return None

        version_strings = []
        for v in versions_raw:
            ver = v.get("version") if isinstance(v, dict) else (v if isinstance(v, str) else None)
            if ver and isinstance(ver, str) and ver.strip():
                version_strings.append(ver.strip())

        if not version_strings:
            return None

        def _semver_key(v: str) -> Tuple[int, ...]:
            try:
                return tuple(int(x) for x in v.lstrip("v").split(".") if x.isdigit())
            except Exception:
                return (0,)

        sorted_versions = sorted(version_strings, key=_semver_key, reverse=True)
        latest_version = sorted_versions[0]
        published_at: Optional[str] = None
        latest_protocols: Optional[str] = None

        for v in versions_raw:
            if isinstance(v, dict) and v.get("version") == latest_version:
                raw_pub = v.get("published_at") or v.get("created_at")
                if raw_pub and isinstance(raw_pub, str):
                    published_at = raw_pub
                    try:
                        dt = datetime.fromisoformat(raw_pub.replace("Z", "+00:00"))
                        published_at = dt.strftime("%Y-%m-%d")
                    except Exception:
                        published_at = raw_pub[:10]
                protos = v.get("protocols")
                if isinstance(protos, list) and protos:
                    latest_protocols = ", ".join(str(p) for p in protos)
                break

        return {
            "latest_version": latest_version,
            "published_at": published_at,
            "versions": sorted_versions,
            "registry_address": f"{namespace}/{provider_type}",
            "indexed_version_count": len(version_strings),
            "latest_protocols": latest_protocols,
        }

    except Exception as e:
        logger.warning(
            "Error fetching Terraform Registry info for %s/%s: %s",
            namespace, provider_type, e,
        )
        return None


def _compare_semver(v1: str, v2: str) -> int:
    def _key(v: str) -> Tuple[int, ...]:
        try:
            return tuple(int(x) for x in v.lstrip("v").split(".") if x.isdigit())
        except Exception:
            return (0,)

    k1, k2 = _key(v1), _key(v2)
    if k1 < k2:
        return -1
    if k1 > k2:
        return 1
    return 0


def build_terraform_provider_details(
    provider_source: Optional[str],
    provider_type_hint: Optional[str],
    cloud_label: str,
    detected_version: Optional[str] = None,
    registry_info: Optional[Dict[str, Any]] = None,
) -> Tuple[str, str, Optional[str], Optional[str]]:
    display_name = cloud_label if cloud_label and cloud_label != "Other" else (
        (provider_source or provider_type_hint or "Unknown").rsplit("/", 1)[-1].title()
    )

    if registry_info:
        latest = registry_info.get("latest_version")
        published_at = registry_info.get("published_at")
        reg_addr = registry_info.get("registry_address")

        if detected_version and latest:
            cmp = _compare_semver(detected_version, latest)
            if cmp >= 0:
                status = "up-to-date"
                version_line = (
                    f"You are using the latest version ({detected_version})."
                )
            else:
                def _major(v: str) -> int:
                    try:
                        return int(v.lstrip("v").split(".")[0])
                    except Exception:
                        return 0
                if _major(latest) > _major(detected_version):
                    status = "outdated"
                else:
                    status = "update-available"
                version_line = (
                    f"Your version is ({detected_version})."
                    f"The latest version is {latest}"
                    + (f", released on {published_at}." if published_at else ".")
                )
        elif latest:
            status = "supported"
            version_line = f"Latest available version: {latest}."
        else:
            status = "unknown"
            version_line = "Could not determine the latest version from the registry."

        sentences: List[str] = []
        sentences.append(
            f"This is the {display_name} Terraform provider"
            + (f" (registry.terraform.io/providers/{reg_addr})." if reg_addr else ".")
        )
        sentences.append(version_line)
        if latest and reg_addr:
            sentences.append(
                f"You can upgrade to {latest} — see "
                f"https://registry.terraform.io/providers/{reg_addr}/latest for changelog and docs."
            )

        details = " ".join(sentences)
        return details, status, latest, published_at

    # Fallback: no registry data
    parts: List[str] = []
    if provider_source:
        parts.append(f"source={provider_source}")
    elif provider_type_hint:
        parts.append(f"provider={provider_type_hint}")
    if cloud_label and cloud_label != "Other":
        parts.append(f"cloud={cloud_label}")
    meta = ", ".join(parts) if parts else "metadata unavailable"
    fallback_details = (
        "Terraform provider EOL data is unavailable from endoflife.date; "
        f"version inventory only ({meta})."
    )
    return fallback_details, "unknown", None, None


@dataclass
class EolResult:
    product: str
    current_version: Optional[str]
    parent_version: Optional[str]
    eol: Optional[str]
    support: Optional[str]
    lts: Optional[bool]
    latest: Optional[str]
    releaseDate: Optional[str]
    status: str
    details: str
    source_files: Optional[List[str]] = None


# ---------------------- Version extraction helpers ----------------------

GO_VERSION_RE = re.compile(r"(?m)^\s*go\s+(\d+\.\d+(?:\.\d+)?)\s*$")
GRADLE_DIST_RE = re.compile(r"distributionUrl=.*gradle-([0-9.]+)-")
MAVEN_DIST_RE = re.compile(r"distributionUrl=.*apache-maven/([0-9.]+)/.*apache-maven-\1-")

GRADLE_TOOLCHAIN_RE = re.compile(r"languageVersion\s*=\s*JavaLanguageVersion\.of\((\d+)\)")
GRADLE_SOURCE_COMPAT_RE = re.compile(r"sourceCompatibility\s*=\s*(?:JavaVersion\.VERSION_)?(\d+)")
GRADLE_TARGET_COMPAT_RE = re.compile(r"targetCompatibility\s*=\s*(?:JavaVersion\.VERSION_)?(\d+)")
GRADLE_RELEASE_RE = re.compile(r"(?m)^\s*options\.release\s*=\s*(\d+)\s*$")
KOTLIN_JVM_TARGET_RE = re.compile(r'jvmTarget\s*=\s*["\'](\d+(?:\.\d+)?)["\']')

NODE_VERSION_TOKEN_RE = re.compile(r"\d+(?:\.\d+){0,2}")
PYTHON_VERSION_TOKEN_RE = re.compile(r"\d+\.\d+(?:\.\d+)?")
TERRAFORM_VERSION_TOKEN_RE = re.compile(r"\d+(?:\.\d+){0,2}")


def parse_engines_node_version(package_json_text: str) -> Optional[str]:
    if not package_json_text or not package_json_text.strip():
        return None
    try:
        data = json.loads(package_json_text)
    except Exception:
        return None
    engines = data.get("engines")
    if not isinstance(engines, dict):
        return None
    node = engines.get("node")
    if not node or not isinstance(node, str):
        return None
    spec = node.strip().strip("\"'")
    if not spec:
        return None
    m = NODE_VERSION_TOKEN_RE.search(spec)
    return m.group(0) if m else None


def parse_nvmrc_version(nvmrc_text: str) -> Optional[str]:
    if not nvmrc_text:
        return None
    for raw in nvmrc_text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        lower = line.lower()
        if lower.startswith("lts/") or lower == "lts":
            continue
        if line.startswith("v") and len(line) > 1 and line[1].isdigit():
            line = line[1:]
        m = NODE_VERSION_TOKEN_RE.search(line)
        return m.group(0) if m else None
    return None


def _extract_first_python_version_token(spec: str) -> Optional[str]:
    if not spec or not isinstance(spec, str):
        return None
    m = PYTHON_VERSION_TOKEN_RE.search(spec)
    return m.group(0) if m else None


def parse_python_version_from_requirements(requirements_text: str) -> Optional[str]:
    if not requirements_text or not requirements_text.strip():
        return None

    for raw in requirements_text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        lower = line.lower()
        if lower.startswith(("-r ", "--requirement ", "-c ", "--constraint ")):
            continue
        if lower.startswith(("-e ", "--editable ")):
            continue
        if lower.startswith("--"):
            continue
        if " #" in line:
            line = line.split(" #", 1)[0].rstrip()
        if " @ " in line:
            line = line.split(" @ ", 1)[0].strip()

        m = re.match(r"(?i)^\s*python\s*([<>=!~]{1,2})\s*([^\s,;]+)", line)
        if not m:
            continue
        version_token = _extract_first_python_version_token(m.group(2))
        if version_token:
            return version_token

    return None


def parse_pipfile_python_version(pipfile_text: str) -> Optional[str]:
    if not pipfile_text or not pipfile_text.strip():
        return None

    in_requires = False
    found_python_version: Optional[str] = None

    for raw in pipfile_text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue

        if line.startswith("[") and line.endswith("]"):
            section = line.strip("[]").strip().lower()
            in_requires = section == "requires"
            continue

        if not in_requires:
            continue

        m = re.match(r"^(python_full_version|python_version)\s*=\s*(.+)$", line, flags=re.I)
        if not m:
            continue

        key = m.group(1).strip().lower()
        value = m.group(2).strip().strip("\"'")
        token = _extract_first_python_version_token(value)
        if not token:
            continue

        if key == "python_full_version":
            return token
        if key == "python_version" and found_python_version is None:
            found_python_version = token

    return found_python_version


def parse_pyproject_python_version(pyproject_text: str) -> Optional[str]:
    if not pyproject_text or not pyproject_text.strip():
        return None

    m = re.search(r"(?im)^\s*requires-python\s*=\s*['\"]([^'\"]+)['\"]\s*$", pyproject_text)
    if m:
        token = _extract_first_python_version_token(m.group(1))
        if token:
            return token

    in_poetry_deps = False
    for raw in pyproject_text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue

        if line.startswith("[") and line.endswith("]"):
            section = line.strip("[]").strip().lower()
            in_poetry_deps = section == "tool.poetry.dependencies"
            continue

        if not in_poetry_deps:
            continue

        m2 = re.match(r"(?i)^\s*python\s*=\s*['\"]([^'\"]+)['\"]\s*$", line)
        if not m2:
            continue
        token = _extract_first_python_version_token(m2.group(1))
        if token:
            return token

    return None


def parse_go_version(go_mod_text: str) -> Optional[str]:
    m = GO_VERSION_RE.search(go_mod_text or "")
    return m.group(1) if m else None


def parse_gradle_wrapper_version(props_text: str) -> Optional[str]:
    m = GRADLE_DIST_RE.search(props_text or "")
    return m.group(1) if m else None


def parse_maven_wrapper_version(props_text: str) -> Optional[str]:
    if not props_text:
        logger.debug("parse_maven_wrapper_version: Empty props_text provided")
        return None
    m = MAVEN_DIST_RE.search(props_text)
    if m:
        version = m.group(1)
        logger.debug(f"parse_maven_wrapper_version: Detected version '{version}' from maven-wrapper.properties")
        return version
    else:
        logger.debug(f"parse_maven_wrapper_version: No version match found. Pattern: {MAVEN_DIST_RE.pattern}")
        logger.debug(f"parse_maven_wrapper_version: Sample content (first 200 chars): {props_text[:200]}")
        return None


def parse_gradle_java_version(build_text: str) -> Optional[str]:
    t = build_text or ""
    m = GRADLE_TOOLCHAIN_RE.search(t)
    if m:
        return m.group(1)

    m = GRADLE_RELEASE_RE.search(t)
    if m:
        return m.group(1)

    candidates = []
    for rx in (GRADLE_SOURCE_COMPAT_RE, GRADLE_TARGET_COMPAT_RE):
        mm = rx.search(t)
        if mm:
            candidates.append(mm.group(1))
    if candidates:
        return str(max(int(x) for x in candidates))

    m = KOTLIN_JVM_TARGET_RE.search(t)
    if m:
        return m.group(1)

    return None


def parse_maven_java_version(pom_text: str) -> Optional[str]:
    if not pom_text:
        return None

    try:
        root = ET.fromstring(pom_text)
    except Exception:
        return None

    ns_match = re.match(r"\{(.+)\}", root.tag)
    ns = {"m": ns_match.group(1)} if ns_match else {}

    props = {}
    props_el = root.find("m:properties", ns) if ns_match else root.find("properties")
    if props_el is not None:
        for child in list(props_el):
            tag = child.tag
            if ns_match:
                tag = re.sub(r"^\{.+\}", "", tag)
            if child.text and child.text.strip():
                props[tag] = child.text.strip()

    for k in ["maven.compiler.release", "maven.compiler.source", "maven.compiler.target", "java.version"]:
        v = props.get(k)
        if v:
            return v

    rx = re.compile(r"<(?:release|source|target)>\s*([^<\s]+)\s*</(?:release|source|target)>")
    m = rx.search(pom_text)
    if m:
        version = m.group(1).strip()
        return version

    return None


def normalize_java_current_version(v: str) -> Optional[str]:
    if not v:
        return None
    vv = v.strip()
    if vv == "1.8":
        return "8"
    m = re.match(r"^(\d+)", vv)
    if m:
        result = m.group(1)
        return result
    return None


def normalize_semver_current_version(v: str) -> Optional[str]:
    if not v:
        return None
    vv = v.strip()
    m = re.match(r"^(\d+)\.(\d+)", vv)
    if m:
        result = f"{m.group(1)}.{m.group(2)}"
        logger.debug(f"normalize_semver_current_version: '{vv}' -> '{result}' (major.minor)")
        return result
    m = re.match(r"^(\d+)", vv)
    if m:
        result = m.group(1)
        logger.debug(f"normalize_semver_current_version: '{vv}' -> '{result}' (major only)")
        return result
    logger.debug(f"normalize_semver_current_version: Failed to extract version from '{vv}'")
    return None


def _extract_hcl_block(text: str, start_index: int) -> Optional[Tuple[str, int]]:
    if not text or start_index < 0 or start_index >= len(text) or text[start_index] != "{":
        return None
    depth = 0
    i = start_index
    while i < len(text):
        ch = text[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[start_index + 1:i], i
        i += 1
    return None


def parse_terraform_provider_version_token(version_constraint: str) -> Optional[str]:
    if not version_constraint:
        return None
    m = TERRAFORM_VERSION_TOKEN_RE.search(version_constraint)
    return m.group(0) if m else None


_TERRAFORM_BLOCK_START = re.compile(r"(?m)^\s*terraform\s*\{", flags=re.I)
_REQUIRED_VERSION_DOUBLE = re.compile(r'(?im)required_version\s*=\s*"([^"]+)"')
_REQUIRED_VERSION_SINGLE = re.compile(r"(?im)required_version\s*=\s*'([^']+)'")


def parse_terraform_required_version(tf_text: str) -> Optional[str]:
    if not tf_text:
        return None
    search_from = 0
    while True:
        m = _TERRAFORM_BLOCK_START.search(tf_text, search_from)
        if not m:
            break
        open_brace_idx = tf_text.find("{", m.start())
        if open_brace_idx == -1:
            break
        extracted = _extract_hcl_block(tf_text, open_brace_idx)
        if not extracted:
            break
        body, end_idx = extracted
        rv_m = _REQUIRED_VERSION_DOUBLE.search(body)
        constraint = (rv_m.group(1).strip() if rv_m else "") or ""
        if not constraint:
            rv_s = _REQUIRED_VERSION_SINGLE.search(body)
            if rv_s:
                constraint = rv_s.group(1).strip()
        if constraint:
            token = parse_terraform_provider_version_token(constraint)
            if token:
                return token
        search_from = end_idx + 1
    return None


def terraform_provider_key(block_label: str, source: Optional[str]) -> str:
    provider_name = (block_label or "").strip().lower()
    src = (source or "").strip().lower()
    if "/" in src:
        provider_name = src.rsplit("/", 1)[-1]
    provider_name = re.sub(r"[^a-z0-9_]+", "_", provider_name).strip("_")
    if not provider_name:
        provider_name = "unknown"
    return f"terraform_provider_{provider_name}"


def parse_required_providers_from_tf(tf_text: str) -> List[Dict[str, Optional[str]]]:
    if not tf_text:
        return []
    providers: List[Dict[str, Optional[str]]] = []
    search_from = 0
    block_pattern = re.compile(r"required_providers\s*\{", flags=re.I)
    provider_start_pattern = re.compile(r"(?m)^\s*([A-Za-z0-9_-]+)\s*=")
    while True:
        m = block_pattern.search(tf_text, search_from)
        if not m:
            break
        open_brace_idx = tf_text.find("{", m.start())
        if open_brace_idx == -1:
            break
        extracted = _extract_hcl_block(tf_text, open_brace_idx)
        if not extracted:
            break
        body, end_idx = extracted
        pos = 0
        while True:
            entry = provider_start_pattern.search(body, pos)
            if not entry:
                break
            block_label = entry.group(1).strip()
            rhs_index = entry.end()
            while rhs_index < len(body) and body[rhs_index].isspace():
                rhs_index += 1

            source: Optional[str] = None
            version: Optional[str] = None
            provider_end_idx = entry.end()

            if rhs_index < len(body) and body[rhs_index] == "{":
                provider_block = _extract_hcl_block(body, rhs_index)
                if provider_block:
                    provider_body, provider_end_idx = provider_block
                    source_match = re.search(
                        r'(?im)\bsource\s*=\s*["\']?([^"\'\n]+)["\']?',
                        provider_body,
                    )
                    version_match = re.search(
                        r'(?im)\bversion\s*=\s*["\']([^"\']+)["\']',
                        provider_body,
                    )
                    source = source_match.group(1).strip() if source_match else None
                    version = version_match.group(1).strip() if version_match else None
            else:
                line_end = body.find("\n", rhs_index)
                if line_end == -1:
                    line_end = len(body)
                rhs = body[rhs_index:line_end].strip()
                rhs = rhs.split("#", 1)[0].split("//", 1)[0].strip()
                if rhs.startswith(("'", '"')) and rhs.endswith(("'", '"')) and len(rhs) >= 2:
                    version = rhs[1:-1].strip()
                elif rhs:
                    version = rhs
                provider_end_idx = line_end

            providers.append(
                {
                    "block_label": block_label,
                    "source": source,
                    "version": version,
                    "version_token": parse_terraform_provider_version_token(version or ""),
                }
            )
            pos = provider_end_idx + 1
        search_from = end_idx + 1
    return providers


def parse_provider_blocks_from_tf(tf_text: str) -> List[Dict[str, Optional[str]]]:
    if not tf_text:
        return []

    providers: List[Dict[str, Optional[str]]] = []
    search_from = 0
    provider_start_re = re.compile(r'provider\s+"([^"]+)"\s*\{', flags=re.I)

    while True:
        m = provider_start_re.search(tf_text, search_from)
        if not m:
            break

        block_label = (m.group(1) or "").strip()
        open_brace_idx = tf_text.find("{", m.start())
        if open_brace_idx == -1:
            break

        extracted = _extract_hcl_block(tf_text, open_brace_idx)
        if not extracted:
            break

        body, end_idx = extracted
        version_match = re.search(
            r'(?im)\bversion\s*=\s*["\']?([^"\'\n]+)["\']?',
            body,
        )
        version = version_match.group(1).strip() if version_match else None
        version_token = parse_terraform_provider_version_token(version or "")

        providers.append(
            {
                "block_label": block_label or None,
                "source": None,
                "version": version,
                "version_token": version_token,
            }
        )
        search_from = end_idx + 1

    return providers


def parse_terraform_lock_providers(lock_text: str) -> Dict[str, Dict[str, Optional[str]]]:
    out: Dict[str, Dict[str, Optional[str]]] = {}
    if not lock_text:
        return out
    search_from = 0
    provider_start_re = re.compile(r'provider\s+"([^"]+)"\s*\{', flags=re.I)
    while True:
        m = provider_start_re.search(lock_text, search_from)
        if not m:
            break
        provider_ref = m.group(1).strip()
        open_brace_idx = lock_text.find("{", m.start())
        if open_brace_idx == -1:
            break
        extracted = _extract_hcl_block(lock_text, open_brace_idx)
        if not extracted:
            break
        body, end_idx = extracted
        version_match = re.search(
            r'(?im)^\s*version\s*=\s*["\']([^"\']+)["\']\s*$',
            body,
        )
        if not version_match:
            search_from = end_idx + 1
            continue
        version = version_match.group(1).strip()
        source = provider_ref
        if source.startswith("registry.terraform.io/"):
            source = source[len("registry.terraform.io/"):]
        out[source.lower()] = {
            "source": source,
            "version": version,
            "version_token": parse_terraform_provider_version_token(version),
        }
        search_from = end_idx + 1
    return out


# ---------------------- endoflife.date integration ----------------------

def eol_fetch_product(slug: str) -> Optional[List[dict]]:
    """
    Return endoflife.date releases for *slug*.
    Priority: MongoDB cache → live endoflife.date API.
    """
    # 1. Try MongoDB cache first
    cached = _mongo_fetch_endoflife(slug)
    if cached is not None:
        return cached

    # 2. Fall back to live API
    import requests
    logger.debug("EOL cache miss; fetching live for slug=%s", slug)
    urls = [
        f"https://endoflife.date/api/v1/products/{slug}/",
        f"https://endoflife.date/api/v1/products/{slug}.json",
        f"https://endoflife.date/api/v1/products/{slug}",
    ]
    headers = {"User-Agent": "repo-lang-version-scanner/1.1"}

    for url in urls:
        try:
            r = requests.get(url, headers=headers, timeout=30)
            if r.status_code == 404:
                continue

            content_type = r.headers.get("Content-Type", "").lower()
            if "application/json" not in content_type and "text/json" not in content_type:
                continue

            r.raise_for_status()
            data = r.json()

            if isinstance(data, dict) and "result" in data:
                releases = data.get("result", {}).get("releases")
                if isinstance(releases, list) and len(releases) > 0:
                    return releases

            if isinstance(data, list) and len(data) > 0:
                return data

        except Exception as e:
            logger.debug(f"Exception for {url}: {e}, trying next URL")
            continue

    logger.warning(f"Failed to fetch EOL data for {slug} from MongoDB cache and live API")
    return None


def parse_date_yyyy_mm_dd(s: Optional[str]) -> Optional[date]:
    if not s or s is False:
        return None
    if not isinstance(s, str):
        return None
    try:
        return datetime.strptime(s, "%Y-%m-%d").date()
    except Exception:
        return None


def choose_best_current_version(records: List[dict], desired_current_version: str) -> Optional[dict]:
    if not records or not desired_current_version:
        return None

    def get_current_version(r: dict) -> str:
        c = r.get("name") or r.get("current_version")
        return str(c) if c is not None else ""

    for r in records:
        if get_current_version(r) == desired_current_version:
            logger.debug(f"Exact match found: {desired_current_version}")
            return r

    for r in records:
        c = get_current_version(r)
        if c.startswith(desired_current_version) or desired_current_version.startswith(c):
            logger.debug(f"Prefix match found: {desired_current_version} <-> {c}")
            return r

    major = desired_current_version.split(".", 1)[0]
    for r in records:
        c = get_current_version(r)
        if c.split(".", 1)[0] == major:
            return r

    return None


def summarize_eol(product_key: str, slug: str, detected_version: str) -> Optional[EolResult]:
    logger.debug(f"summarize_eol called: product_key={product_key}, slug={slug}, detected_version={detected_version}")

    records = eol_fetch_product(slug)
    if not records:
        logger.warning(f"No EOL records found for {product_key} (slug: {slug})")
        return EolResult(
            product=product_key,
            current_version=detected_version,
            parent_version=None,
            eol=None,
            support=None,
            lts=None,
            latest=None,
            releaseDate=None,
            status="unknown",
            details="No data returned from endoflife.date for this product.",
        )

    logger.debug(f"Retrieved {len(records)} EOL records for {slug}")

    if product_key == "java":
        desired_current_version = normalize_java_current_version(detected_version)
    else:
        desired_current_version = normalize_semver_current_version(detected_version)

    logger.debug(f"Normalized current_version: detected_version={detected_version} -> desired_current_version={desired_current_version}")

    if not desired_current_version:
        logger.warning(f"Failed to normalize version '{detected_version}' for {product_key}")
        return EolResult(
            product=product_key,
            current_version=detected_version,
            parent_version=None,
            eol=None,
            support=None,
            lts=None,
            latest=None,
            releaseDate=None,
            status="unknown",
            details="Could not normalize detected version into an endoflife.date current_version.",
        )

    rec = choose_best_current_version(records, desired_current_version)
    if not rec:
        logger.warning(f"No matching current_version found for {product_key}. Desired: '{desired_current_version}'")
        return EolResult(
            product=product_key,
            current_version=detected_version,
            parent_version=None,
            eol=None,
            support=None,
            lts=None,
            latest=None,
            releaseDate=None,
            status="unknown",
            details=f"No matching current_version found in endoflife.date for current_version '{desired_current_version}'.",
        )

    is_eol = rec.get("isEol")
    eol_from = rec.get("eolFrom")
    is_maintained = rec.get("isMaintained")
    eol_raw = rec.get("eol")
    support_raw = rec.get("support")

    eol_dt = None
    today = date.today()

    if is_eol is not None:
        if is_eol:
            eol_dt = parse_date_yyyy_mm_dd(eol_from)
            if eol_dt:
                status = "eol" if today > eol_dt else "supported"
                details = f"EOL date is {eol_dt.isoformat()}."
            else:
                status = "eol" if is_eol else "supported"
                details = f"EOL status: {is_eol}, eolFrom: {eol_from}"
        else:
            status = "supported"
            details = "Still supported (isEol=False per API)."
    elif eol_raw is not None:
        if eol_raw is False:
            status = "supported"
            details = "No EOL date listed (still supported per API)."
        else:
            eol_dt = parse_date_yyyy_mm_dd(eol_raw)
            if eol_dt:
                status = "eol" if today > eol_dt else "supported"
                details = f"EOL date is {eol_dt.isoformat()}."
            else:
                status = "unknown"
                details = f"EOL field present but not a YYYY-MM-DD date: {eol_raw!r}"
    else:
        status = "unknown"
        details = "No EOL information available in API response."

    parent_version = rec.get("name") or rec.get("current_version")

    latest_obj = rec.get("latest")
    if isinstance(latest_obj, dict):
        latest_version = latest_obj.get("name")
    else:
        latest_version = latest_obj

    eol_date_str = None
    if eol_from:
        eol_date_str = str(eol_from)
    elif eol_raw and eol_raw is not False:
        eol_date_str = str(eol_raw)

    support_date_str = None
    if support_raw:
        support_date_str = str(support_raw)
    elif is_maintained is not None:
        support_date_str = "maintained" if is_maintained else "not maintained"

    result = EolResult(
        product=product_key,
        current_version=detected_version,
        parent_version=str(parent_version) if parent_version is not None else None,
        eol=eol_date_str,
        support=support_date_str,
        lts=rec.get("lts") if isinstance(rec.get("lts"), bool) else rec.get("isLts"),
        latest=str(latest_version) if latest_version is not None else None,
        releaseDate=rec.get("releaseDate") if rec.get("releaseDate") is not None else None,
        status=status,
        details=details,
    )

    logger.info(f"EOL check successful for {product_key}: version={detected_version}, current_version={result.parent_version}, status={status}")
    return result


def _normalize_detected_versions(
    detected: Union[None, str, List[str], tuple, set]
) -> List[str]:
    if detected is None:
        return []
    if isinstance(detected, str):
        values = [detected]
    elif isinstance(detected, (list, tuple, set)):
        values = [str(v) for v in detected if v is not None]
    else:
        values = [str(detected)]

    cleaned = []
    seen = set()
    for value in values:
        version = str(value).strip()
        if not version:
            continue
        if version in seen:
            continue
        seen.add(version)
        cleaned.append(version)
    return cleaned


def _build_output_key(product_key: str, detected_version: str, total_for_product: int) -> str:
    if total_for_product <= 1:
        return product_key

    if product_key == "java":
        current_version_suffix = normalize_java_current_version(detected_version) or detected_version
    else:
        current_version_suffix = normalize_semver_current_version(detected_version) or detected_version
    current_version_suffix = re.sub(r"\s+", "", str(current_version_suffix))
    return f"{product_key}_{current_version_suffix}"


def _strip_nulls(d: dict) -> dict:
    return {k: v for k, v in d.items() if v is not None}


def check_eol_for_versions_with_origins(
    versions: Dict[str, Union[Optional[str], List[str]]],
    origins: Dict[str, Dict[str, List[str]]],
    terraform_provider_meta: Optional[Dict[str, Dict[str, Optional[str]]]] = None,
) -> Dict[str, Optional[dict]]:

    eol_results: Dict[str, Optional[dict]] = {}
    _tf_meta: Dict[str, Dict[str, Optional[str]]] = terraform_provider_meta or {}

    # Cache for Terraform Registry lookups (mongo-backed via fetch_terraform_provider_registry_info)
    _tf_registry_cache: Dict[str, Optional[Dict[str, Any]]] = {}

    # Accumulate provider entries for the dedicated terraformProviders block
    terraform_providers_block: Dict[str, dict] = {}

    # ========== Standard runtimes / build tools ==========
    for key, slug in EOL_PRODUCT_SLUGS.items():
        detected_versions = _normalize_detected_versions(versions.get(key))
        if not detected_versions:
            continue

        for detected_version in detected_versions:
            eol_res = summarize_eol(key, slug, detected_version)
            output_key = _build_output_key(key, detected_version, len(detected_versions))
            if eol_res is None:
                eol_results[output_key] = None
                continue

            res_dict = asdict(eol_res)
            product_origins = origins.get(key, {})
            paths = product_origins.get(detected_version) or []
            if paths:
                res_dict["source_files"] = sorted({str(p) for p in paths})
            eol_results[output_key] = res_dict

    # ========== Terraform providers ==========
    for key, detected in versions.items():
        if not isinstance(key, str) or not key.startswith("terraform_provider_"):
            continue
        detected_versions = _normalize_detected_versions(detected)
        if not detected_versions:
            continue

        meta = _tf_meta.get(key, {})
        provider_source: Optional[str] = meta.get("source") if meta else None
        type_tail = key[len("terraform_provider_"):]
        provider_type_hint: Optional[str] = type_tail or None

        cloud_label = classify_terraform_cloud_provider(
            provider_type_hint, provider_source
        )

        registry_info: Optional[Dict[str, Any]] = None
        namespace: Optional[str] = None
        provider_type: Optional[str] = None

        if provider_source:
            namespace, provider_type = _parse_provider_source(provider_source)
            cache_key = provider_source.lower().strip()
            if cache_key not in _tf_registry_cache:
                if namespace and provider_type:
                    _tf_registry_cache[cache_key] = fetch_terraform_provider_registry_info(
                        namespace, provider_type
                    )
                else:
                    _tf_registry_cache[cache_key] = None
            registry_info = _tf_registry_cache.get(cache_key)
        elif provider_type_hint:
            namespace, provider_type = "hashicorp", provider_type_hint.lower()
            cache_key = f"hashicorp/{provider_type_hint}".lower()
            if cache_key not in _tf_registry_cache:
                _tf_registry_cache[cache_key] = fetch_terraform_provider_registry_info(
                    namespace, provider_type
                )
            registry_info = _tf_registry_cache.get(cache_key)

        for detected_version in detected_versions:
            details_str, provider_status, latest_ver, release_date = (
                build_terraform_provider_details(
                    provider_source=provider_source,
                    provider_type_hint=provider_type_hint,
                    cloud_label=cloud_label,
                    detected_version=detected_version,
                    registry_info=registry_info,
                )
            )

            eol_res = EolResult(
                product=key,
                current_version=detected_version,
                parent_version=None,
                eol=None,
                support=None,
                lts=None,
                latest=latest_ver,
                releaseDate=release_date,
                status=provider_status,
                details=details_str,
            )
            output_key = _build_output_key(key, detected_version, len(detected_versions))
            res_dict = asdict(eol_res)

            res_dict["cloudProvider"] = cloud_label
            if provider_source:
                res_dict["providerSource"] = provider_source

            if namespace and provider_type:
                res_dict["registryUrl"] = (
                    f"https://registry.terraform.io/providers/{namespace}/{provider_type}/latest"
                )

            product_origins = origins.get(key, {})
            paths = product_origins.get(detected_version) or []
            if paths:
                res_dict["source_files"] = sorted({str(p) for p in paths})

            res_dict = _strip_nulls(res_dict)

            terraform_providers_block[output_key] = res_dict

    if terraform_providers_block:
        eol_results["terraformProviders"] = terraform_providers_block

    return eol_results


def check_eol_for_versions(
    versions: Dict[str, Union[Optional[str], List[str]]]
) -> Dict[str, Optional[dict]]:
    """Backwards-compatible wrapper that checks EOL status without source file metadata."""
    return check_eol_for_versions_with_origins(versions, origins={})