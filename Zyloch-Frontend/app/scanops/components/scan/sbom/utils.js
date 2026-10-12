// Formats a license name for display
export function formatLicenseName(licenseConcluded) {
  if (!licenseConcluded || licenseConcluded === 'UNKNOWN' || licenseConcluded === 'Unknown' || licenseConcluded === '-') return 'Unknown';
  // Replace dashes/underscores with spaces and capitalize
  const formatted = licenseConcluded
    .replace(/[-_]/g, ' ')
    .replace(/\b\w/g, c => c.toUpperCase())
    .trim();
  return formatted || 'Unknown';
}

// ---------------------------------------------------------------------------

const PACKAGE_MANAGER_TO_PURL_TYPE = {
  python: "pypi", pip: "pypi", pypi: "pypi", poetry: "pypi", pipenv: "pypi", pipfile: "pypi",
  npm: "npm", yarn: "npm", pnpm: "npm", node: "npm", nodejs: "npm", javascript: "npm",
  maven: "maven", mvn: "maven", java_maven: "maven",
  gradle: "maven", java_gradle: "maven",
  go: "golang", golang: "golang", gomod: "golang",
};

function safeDecode(value) {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

// Builds the public registry page for a package, including the version whenever
// the registry exposes a per-version page. Only the ecosystems the scanner
// resolves are handled (PyPI, npm, Maven/Gradle, Go); anything else returns ""
// so the caller can fall back to showing no link.
function buildRegistryUrl(type, namespace, name, version) {
  const t = String(type || "").toLowerCase();
  const ns = namespace ? String(namespace).replace(/^\/+|\/+$/g, "") : "";
  const n = String(name || "").trim();
  const v = version ? String(version).trim() : "";
  if (!n) return "";

  switch (t) {
    case "pypi":
      return v ? `https://pypi.org/project/${n}/${v}/` : `https://pypi.org/project/${n}/`;
    case "npm": {
      const full = ns ? `${ns}/${n}` : n;
      return v ? `https://www.npmjs.com/package/${full}/v/${v}` : `https://www.npmjs.com/package/${full}`;
    }
    case "maven": {
      // Maven coordinates: namespace = groupId, name = artifactId. Also accept a
      // "group:artifact" colon form arriving in either field (non-spec purls and
      // synthesized fallbacks join coordinates with ":" instead of "/").
      let coord = ns ? `${ns}/${n}` : n;
      if (coord.includes(":")) coord = coord.replace(/:/g, "/");
      return v
        ? `https://mvnrepository.com/artifact/${coord}/${v}`
        : `https://mvnrepository.com/artifact/${coord}`;
    }
    case "golang": {
      let modPath = ns ? `${ns}/${n}` : n;
      let goVersion = v && /^\d/.test(v) ? `v${v}` : v;
      const major = Number((goVersion.match(/^v(\d+)\./) || [])[1]);
      // Go modules at major version >= 2 carry a "/vN" suffix in the import path
      // (semantic import versioning); reconstruct it when the purl omits it.
      // Skipped for: gopkg.in paths (different scheme, e.g. gopkg.in/yaml.v2) and
      // "+incompatible" versions, which explicitly opted out of the /vN suffix.
      if (
        major >= 2 &&
        !goVersion.includes("+incompatible") &&
        !modPath.startsWith("gopkg.in/") &&
        !new RegExp(`(^|/)v${major}$`).test(modPath)
      ) {
        modPath = `${modPath}/v${major}`;
      }
      // Pseudo-versions (untagged commits, "...<timestamp>-<commit>") are usually
      // not indexed by pkg.go.dev; link to the module page instead of a dead URL.
      // The timestamp is preceded by "-" (v0.0.0-...) or "." (vX.Y.Z-0....).
      if (/[-.]\d{14}-[0-9a-f]{12}$/.test(goVersion)) goVersion = "";
      return goVersion ? `https://pkg.go.dev/${modPath}@${goVersion}` : `https://pkg.go.dev/${modPath}`;
    }
    default:
      return "";
  }
}

// Parses a Package-URL per the spec:
//   pkg:type/namespace/name@version?qualifiers#subpath
export function parsePackageUrl(purl) {
  if (!purl || typeof purl !== "string") return null;
  const trimmed = purl.trim();
  if (!/^pkg:/i.test(trimmed)) return null;

  let rest = trimmed.slice(4).replace(/^\/+/, "");
  rest = rest.split("#")[0];
  const main = rest.split("?")[0];

  const slash = main.indexOf("/");
  if (slash === -1) return null;
  const type = main.slice(0, slash).toLowerCase();

  let remainder = main.slice(slash + 1);
  let version = "";
  const at = remainder.lastIndexOf("@");
  if (at !== -1) {
    version = safeDecode(remainder.slice(at + 1));
    remainder = remainder.slice(0, at);
  }

  const segments = remainder.split("/").filter(Boolean).map(safeDecode);
  if (segments.length === 0) return null;
  const name = segments.pop();
  const namespace = segments.join("/");

  return { type, namespace, name, version };
}

// Resolves the best browsable URL for a package row:
//   1. an already-usable http(s) link (or a git+https link)
//   2. a registry page derived from its purl
//   3. a registry page synthesized from packageManager + name + version
export function resolvePackageUrl(pkg) {
  if (!pkg) return "";

  const raw = String(pkg.packageURL || "").trim();
  if (/^git\+https?:\/\//i.test(raw)) return raw.replace(/^git\+/i, "");
  if (/^https?:\/\//i.test(raw)) return raw;

  const rowName = String(pkg.moduleName || "").trim();
  const rowVersionRaw = String(pkg.versionInfo || "").trim();
  const rowVersion = rowVersionRaw && rowVersionRaw.toLowerCase() !== "unknown" ? rowVersionRaw : "";

  const parsed = parsePackageUrl(raw);
  if (parsed) {
    let { namespace, name } = parsed;
    // purls are frequently lowercased, but Go / scoped-npm canonical URLs are
    // case-sensitive - prefer the row's module-name casing when it matches.
    const purlPath = namespace ? `${namespace}/${name}` : name;
    if (rowName && rowName !== purlPath && rowName.toLowerCase() === purlPath.toLowerCase()) {
      const parts = rowName.split("/");
      name = parts.pop();
      namespace = parts.join("/");
    }
    // Backfill a missing purl version from the row's own version field.
    const fromPurl = buildRegistryUrl(parsed.type, namespace, name, parsed.version || rowVersion);
    if (fromPurl) return fromPurl;
  }

  const managerKey = String(pkg.packageManager || "").trim().toLowerCase();
  const type = PACKAGE_MANAGER_TO_PURL_TYPE[managerKey] || (parsed ? parsed.type : managerKey);

  if (type && rowName && rowName.toLowerCase() !== "unknown") {
    let namespace = "";
    let name = rowName;
    if (type === "maven" && rowName.includes(":")) {
      [namespace, name] = rowName.split(":");
    } else if ((type === "npm" || type === "golang" || type === "composer") && rowName.includes("/")) {
      const parts = rowName.split("/");
      name = parts.pop();
      namespace = parts.join("/");
    }
    const fromManager = buildRegistryUrl(type, namespace, name, rowVersion);
    if (fromManager) return fromManager;
  }

  return "";
}
// Returns a color variable for a given risk level
export function getRiskColor(riskLevel) {
  switch ((riskLevel || '').toLowerCase()) {
    case 'high':
      return 'var(--danger)';
    case 'medium':
      return 'var(--warning)';
    case 'low':
      return 'var(--success)';
    case 'variable':
      return 'var(--info)';
    default:
      return 'var(--muted)';
  }
}
// --- SBOM Main Helper Logic ---
import { Package, GitCommitHorizontal, User, GitCompare, Calendar, Layers, ShieldAlert, Settings } from "lucide-react";
import LICENSE_POLICY_MAP from "@/data/LICENSE_POLICY_MAP.json";

// Maps common long-form license names (as reported in Maven/Gradle POM metadata, etc.)
// to the SPDX identifiers used as keys in LICENSE_POLICY_MAP.json.
const LICENSE_NAME_ALIASES = {
  "the apache software license, version 2.0": "Apache-2.0",
  "the apache software license, version 1.1": "Apache-1.1",
  "the apache license, version 2.0": "Apache-2.0",
  "apache license, version 2.0": "Apache-2.0",
  "apache license 2.0": "Apache-2.0",
  "apache license v2.0": "Apache-2.0",
  "apache 2.0": "Apache-2.0",
  "apache2": "Apache-2.0",
  "mit license": "MIT",
  "the mit license": "MIT",
  "the mit license (mit)": "MIT",
  "mit license (mit)": "MIT",
  "bsd license": "BSD-3-Clause",
  "new bsd license": "BSD-3-Clause",
  "revised bsd license": "BSD-3-Clause",
  "the bsd 3-clause license": "BSD-3-Clause",
  "bsd 3-clause license": "BSD-3-Clause",
  "the bsd 2-clause license": "BSD-2-Clause",
  "bsd 2-clause license": "BSD-2-Clause",
  "bsd 2 clause": "BSD-2-Clause",
  "bsd 2-clause": "BSD-2-Clause",
  "bsd 3 clause": "BSD-3-Clause",
  "bsd 3-clause": "BSD-3-Clause",
  "isc license": "ISC",
  "eclipse public license 1.0": "EPL-1.0",
  "eclipse public license - v 1.0": "EPL-1.0",
  "eclipse public license 2.0": "EPL-2.0",
  "eclipse public license - v 2.0": "EPL-2.0",
  "gnu lesser general public license, version 2.1": "LGPL-2.1",
  "lgpl 2.1": "LGPL-2.1",
  "gnu lesser general public license, version 3": "LGPL-3.0",
  "lgpl 3.0": "LGPL-3.0",
  "gnu general public license, version 2": "GPL-2.0",
  "gpl 2.0": "GPL-2.0",
  "gnu general public license, version 3": "GPL-3.0",
  "gpl 3.0": "GPL-3.0",
  "gnu affero general public license, version 3": "AGPL-3.0",
  "mozilla public license 2.0": "MPL-2.0",
  "mozilla public license, version 2.0": "MPL-2.0",
  "creative commons cc0": "CC0-1.0",
  "cc0 1.0 universal": "CC0-1.0",
  "the unlicense": "Unlicense",
  "zlib license": "Zlib",
};

// Keyword/regex fallback for license text whose wording or word order doesn't match
// LICENSE_NAME_ALIASES verbatim (e.g. "3 Clause BSD License" vs "BSD 3-Clause License").
// Ordered most-specific first. Where a family has multiple versions (GPL-2.0/3.0, etc.),
// LICENSE_POLICY_MAP.json currently gives every version in that family the same riskLevel,
// so picking a default version here does not change the resulting risk classification.
const LICENSE_TEXT_PATTERNS = [
  [/\bbsd\b.{0,20}\b3[- ]?clause\b|\b3[- ]?clause\b.{0,20}\bbsd\b|\b(new|modified|revised)\s+bsd\b/i, "BSD-3-Clause"],
  [/\bbsd\b.{0,20}\b2[- ]?clause\b|\b2[- ]?clause\b.{0,20}\bbsd\b/i, "BSD-2-Clause"],
  [/\bbsd\b/i, "BSD-3-Clause"],
  [/\bapache\b.{0,15}\b1\.1\b|\b1\.1\b.{0,15}\bapache\b/i, "Apache-1.1"],
  [/\bapache\b/i, "Apache-2.0"],
  [/\baffero\b|\bagpl\b/i, "AGPL-3.0"],
  [/\b(lgpl|lesser general public license)\b.{0,15}\b3(\.0)?\b/i, "LGPL-3.0"],
  [/\blgpl\b|\blesser general public license\b/i, "LGPL-2.1"],
  [/\b(gpl|general public license)\b.{0,15}\b3(\.0)?\b/i, "GPL-3.0"],
  [/\bgpl\b|\bgeneral public license\b/i, "GPL-2.0"],
  [/\bmpl\b|\bmozilla public license\b/i, "MPL-2.0"],
  [/\b(eclipse public license|epl)\b.{0,15}\b1(\.0)?\b/i, "EPL-1.0"],
  [/\beclipse public license\b|\bepl\b/i, "EPL-2.0"],
  [/\bmit\b/i, "MIT"],
  [/\bisc\b/i, "ISC"],
  [/\bzlib\b/i, "Zlib"],
  [/\bunlicense\b/i, "Unlicense"],
  [/\bcc0\b|\bpublic domain\b/i, "CC0-1.0"],
  [/\bwtfpl\b/i, "WTFPL"],
];

// Resolves a raw license string to the key LICENSE_POLICY_MAP actually uses,
// falling back to the original string (and eventually NOASSERTION) if unrecognized.
function resolveLicenseKey(licenseConcluded) {
  if (LICENSE_POLICY_MAP[licenseConcluded]) return licenseConcluded;
  const normalized = String(licenseConcluded).trim().toLowerCase();
  if (LICENSE_NAME_ALIASES[normalized]) return LICENSE_NAME_ALIASES[normalized];
  const patternMatch = LICENSE_TEXT_PATTERNS.find(([pattern]) => pattern.test(licenseConcluded));
  if (patternMatch) return patternMatch[1];
  return licenseConcluded;
}

export const CONFIG = {
  LAYOUT: {
    TABLE_ITEMS_PER_PAGE: 50,
    GRID_ITEMS_PER_PAGE: 12,
    CHART_BAR_SIZE: 32,
    STAT_CARD_HEIGHT: "auto",
    SPACING: {
      PAGE_GAP: "var(--space-6)",
      SECTION_GAP: "var(--space-6)",
      CARD_GAP: "var(--space-4)",
      ELEMENT_GAP: "var(--space-4)",
      PADDING: "var(--space-5)",
    },
    BORDERS: {
      RADIUS: "var(--radius-lg)",
      WIDTH: "1px",
    }
  },
  THEME: {
    FONTS: {
      PRIMARY: "Inter, sans-serif",
      MONO: "var(--font-mono)",
    },
    GRADIENTS: {
      HEADER: "linear-gradient(90deg, color-mix(in srgb, var(--color-primary) 10%, transparent) 0%, color-mix(in srgb, var(--info) 5%, transparent) 50%, transparent 100%)",
      PAGE_BG: "var(--bg)",
    },
  },
  COLORS: {
    PURPLE: { base: "var(--color-primary)", light: "var(--color-primary)", bg: "color-mix(in srgb, var(--color-primary) 10%, transparent)", border: "var(--color-primary)", iconBg: "color-mix(in srgb, var(--color-primary) 20%, transparent)" },
    VIVIOLET: { base: "var(--color-secondary)", light: "var(--color-secondary)", bg: "color-mix(in srgb, var(--color-secondary) 10%, transparent)", border: "var(--color-secondary)" },
    CYAN: { base: "var(--info)", light: "var(--info)", bg: "color-mix(in srgb, var(--info) 10%, transparent)", border: "var(--info)" },
    INDIGO: { base: "var(--color-accent)", light: "var(--color-accent)", bg: "color-mix(in srgb, var(--color-accent) 10%, transparent)", border: "var(--color-accent)" },
    GRAY: { base: "var(--muted)", dark: "var(--muted)", border: "var(--border)", bg: "var(--surface)", surface: "var(--surface)" },
    SUCCESS: "var(--success)",
    WARNING: "var(--warning)",
    DANGER: "var(--danger)",
  }
};

export function getSbomData(latestScan) {
  function normalizeUnknown(value, fallback = "Unknown") {
    if (value === null || value === undefined) return fallback;
    const normalized = String(value).trim();
    if (!normalized || normalized.toLowerCase() === "unknown") return fallback;
    return normalized;
  }
  function normalizePackageUrl(value) {
    if (!value) return "";
    const normalized = String(value).trim();
    if (!normalized || normalized.toLowerCase() === "unknown") return "";
    return normalized;
  }
  function normalizeLicense(value) {
    if (Array.isArray(value)) {
      const first = value.find((item) => {
        if (item === null || item === undefined) return false;
        const s = String(item).trim();
        return s && s !== "-" && s.toLowerCase() !== "unknown";
      });
      return first ? String(first).trim() : "Unknown";
    }
    const str = String(value === null || value === undefined ? "" : value).trim();
    if (!str || str === "-" || str.toLowerCase() === "unknown") return "Unknown";
    return str;
  }
  function normalizeSeverity(severity, fallback = "") {
    if (!severity) return fallback;
    const normalized = String(severity).trim().toLowerCase();
    if (!normalized) return fallback;
    if (normalized === "critical") return "Critical";
    if (normalized === "high") return "High";
    if (normalized === "moderate") return "Medium";
    if (normalized === "medium") return "Medium";
    if (normalized === "low") return "Low";
    return fallback;
  }
  function normalizeOssRisk(value, fallback = "Unknown") {
    if (value === null || value === undefined) return fallback;
    const raw = String(value).trim();
    if (!raw || raw.toLowerCase() === "unknown") return fallback;

    const normalized = raw.toLowerCase();
    if (normalized === "immediate") return "Immediate";
    if (normalized === "monitor") return "Monitor";
    if (normalized === "critical") return "Critical";
    if (normalized === "high") return "High";
    if (normalized === "medium" || normalized === "moderate") return "Medium";
    if (normalized === "low") return "Low";
    return raw;
  }
  function pickHighestOssRiskFromVulns(vulns) {
    if (!Array.isArray(vulns)) return "";
    const rank = { Immediate: 6, Critical: 5, High: 4, Medium: 3, Low: 2, Monitor: 1 };
    let best = "";

    for (const vuln of vulns) {
      const current = normalizeOssRisk(vuln?.oss_risk, "");
      if (!current) continue;
      if (!best || (rank[current] || 0) > (rank[best] || 0)) {
        best = current;
      }
    }

    return best;
  }
  function pickHighestSeverityFromValues(values) {
    const severityRank = { Critical: 4, High: 3, Medium: 2, Low: 1 };
    let highest = "";

    const visit = (value) => {
      if (value === null || value === undefined) return;

      if (Array.isArray(value)) {
        value.forEach(visit);
        return;
      }

      if (typeof value === "object") {
        const candidate = normalizeSeverity(
          value?.severity ||
          value?.cvss_severity ||
          value?.cvssSeverity ||
          value?.level ||
          value?.rating,
          ""
        );
        if (candidate && (!highest || severityRank[candidate] > severityRank[highest])) {
          highest = candidate;
        }
        Object.values(value).forEach(visit);
        return;
      }

      const candidate = normalizeSeverity(value, "");
      if (candidate && (!highest || severityRank[candidate] > severityRank[highest])) {
        highest = candidate;
      }
    };

    visit(values);
    return highest;
  }
  function extractModuleName(description) {
    const match = description?.match(/Package:\s*([^\s|]+)/);
    return match ? match[1] : "Unknown";
  }
  function extractVersion(description) {
    const match = description?.match(/\bv([^\s|]+)/);
    return match ? match[1] : "Unknown";
  }
  function extractLicense(description) {
    const match = description?.match(/License:\s*([^\s|]+)/);
    const license = match ? match[1] : "Unknown";
    if (license === "Unknown" || license === "UNKNOWN") return "Unknown";
    return license;
  }
  function extractPackageManager(description) {
    const match = description?.match(/Manager:\s*([^\s|]+)/);
    return match ? match[1] : null;
  }
  function extractCveIds(value) {
    const matches = String(value || "").match(/(?:CVE-\d{4}-\d{4,7}|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}|GO-\d{4}-\d{4,7})/ig) || [];
    return [...new Set(matches.map((item) => item.toUpperCase()))];
  }
  function pickFirstVulnId(vulns) {
    if (!Array.isArray(vulns)) return "";
    for (const v of vulns) {
      const id = v?.cve_id || v?.cveId || v?.vulnerability_id || v?.ghsa_id || v?.id;
      if (id && typeof id === "string" && id.trim()) return id.trim().toUpperCase();
    }
    return "";
  }
  function pickFirstCveFromValues(values) {
    for (const raw of values) {
      if (raw === null || raw === undefined) continue;
      if (Array.isArray(raw)) {
        const fromArray = pickFirstCveFromValues(raw);
        if (fromArray) return fromArray;
        continue;
      }
      if (typeof raw === "object") {
        const fromObject = extractCveIds(JSON.stringify(raw))[0];
        if (fromObject) return fromObject;
        continue;
      }
      const match = extractCveIds(raw)[0];
      if (match) return match;
    }
    return "";
  }
  function resolveCveId(obj, description, moduleFallbackCve = "") {
    // 1. Direct extraction from vulnerabilities array (enriched format)
    const fromVulns = pickFirstVulnId(obj?.vulnerabilities);
    if (fromVulns) return fromVulns;

    const directCandidates = [
      obj?.cveId,
      obj?.cve_id,
      obj?.cve,
      obj?.cves,
      obj?.cveIds,
      obj?.cve_ids,
      obj?.vulnerabilityId,
      obj?.vulnerability_id,
      obj?.vulnerabilityIds,
      obj?.vulnerability_ids,
      obj?.advisoryId,
      obj?.advisory_id,
      obj?.ghsa,
      obj?.identifiers,
      obj?.vulnerability,
      obj?.securityEvents,
      obj?.id,
    ];
    const fromDirect = pickFirstCveFromValues(directCandidates);
    if (fromDirect) return fromDirect;

    const fromDescription = extractCveIds(description)[0];
    if (fromDescription) return fromDescription;

    const fromObjectBody = obj ? extractCveIds(JSON.stringify(obj))[0] : "";
    if (fromObjectBody) return fromObjectBody;

    return moduleFallbackCve;
  }
  function getDependencyName(dep) {
    return normalizeUnknown(
      dep?.moduleName ||
      dep?.name ||
      dep?.packageName ||
      dep?.package_name ||
      dep?.component?.name
    );
  }
  function getDependencyVersion(dep) {
    return normalizeUnknown(
      dep?.versionInfo ||
      dep?.version ||
      dep?.packageVersion ||
      dep?.package_version ||
      dep?.component?.version
    );
  }
  function getDependencyLicense(dep) {
    return normalizeLicense(
      dep?.licenseConcluded ||
      dep?.license ||
      dep?.license_id ||
      dep?.component?.license ||
      dep?.component?.licenses
    );
  }
  function getDependencyPackageManager(dep) {
    return normalizeUnknown(
      dep?.packageManager ||
      dep?.ecosystem ||
      dep?.manager ||
      dep?.package_manager ||
      dep?.component?.ecosystem
    );
  }
  function getDependencyPackageUrl(dep) {
    return normalizePackageUrl(
      dep?.packageURL ||
      dep?.package_url ||
      dep?.purl ||
      dep?.stacks?.spdx?.download_location ||
      dep?.homepage ||
      dep?.url
    );
  }
  function getDependencySourceLocation(dep) {
    return normalizeUnknown(
      dep?.sourceLocation ||
      dep?.source_file ||
      dep?.file ||
      dep?.path,
      ""
    );
  }
  function resolveDependencyOssRisk(dep, moduleOssRisk) {
    const fromVulns = pickHighestOssRiskFromVulns(dep?.vulnerabilities);
    if (fromVulns) return fromVulns;

    const fromDependency = normalizeOssRisk(dep?.oss_risk, "");
    if (fromDependency) return fromDependency;

    return normalizeOssRisk(moduleOssRisk, "");
  }
  function findVulnerabilityById(vulns, selectedCveId) {
    if (!Array.isArray(vulns) || vulns.length === 0) return null;
    const target = String(selectedCveId || "").trim().toUpperCase();
    if (target) {
      const matched = vulns.find((v) => {
        const id = v?.cve_id || v?.cveId || v?.vulnerability_id || v?.ghsa_id || v?.id;
        return String(id || "").trim().toUpperCase() === target;
      });
      if (matched) return matched;
    }
    return vulns[0] || null;
  }
  function asDateText(value, fallback = "Unknown") {
    if (value === null || value === undefined) return fallback;
    const raw = String(value).trim();
    if (!raw) return fallback;
    const dt = new Date(raw);
    if (Number.isNaN(dt.getTime())) return raw;
    const dd = String(dt.getDate()).padStart(2, "0");
    const mm = String(dt.getMonth() + 1).padStart(2, "0");
    const yyyy = dt.getFullYear();
    return `${dd}-${mm}-${yyyy}`;
  }
  function asPercentFromFraction(value, fallback = "N/A") {
    const num = Number(value);
    if (!Number.isFinite(num)) return fallback;
    return `${(num * 100).toFixed(2)}%`;
  }
  function asKevText(value, fallback = "Unknown") {
    if (value === true || String(value).toLowerCase() === "true") return "Yes";
    if (value === false || String(value).toLowerCase() === "false") return "No";
    return fallback;
  }
  function resolveDependencySeverity(dep, moduleSeverity, fallback = "Medium") {
    const fromDependency = pickHighestSeverityFromValues([
      dep?.severity,
      dep?.risk,
      dep?.vulnerabilities,
      dep?.securityEvents,
    ]);
    if (fromDependency) return fromDependency;
    return normalizeSeverity(moduleSeverity, fallback);
  }
  const sbomResults = latestScan?.scan_results?.scans_findings?.["Sbom-findings"] || [];
  const allFindingsGroups = latestScan?.scan_results?.scans_findings || {};
  const cveByModule = new Map();
  const ossRiskByModule = new Map();
  const toModuleKey = (value) => normalizeUnknown(value, "").toLowerCase();

  Object.values(allFindingsGroups).forEach((groupResults) => {
    if (!Array.isArray(groupResults)) return;
    groupResults.forEach((result) => {
      const findings = result?.violated_policies || [];
      findings.forEach((finding) => {
        const description = finding?.description || "";
        const moduleName = normalizeUnknown(finding?.Matches || extractModuleName(description));
        const moduleKey = toModuleKey(moduleName);
        const cve = pickFirstCveFromValues([
          finding?.cveId,
          finding?.cve_id,
          finding?.cves,
          finding?.vulnerabilityId,
          finding?.vulnerability_id,
          description,
          finding?.remediation,
          finding,
        ]);
        if (!cve || !moduleKey) return;
        if (!cveByModule.has(moduleKey)) {
          cveByModule.set(moduleKey, cve);
        }

        const moduleOssRisk = normalizeOssRisk(finding?.oss_risk, "");
        if (moduleOssRisk && !ossRiskByModule.has(moduleKey)) {
          ossRiskByModule.set(moduleKey, moduleOssRisk);
        }
      });
    });
  });

  const severityByModule = new Map(
    sbomResults.flatMap((result) => {
      const findings = result?.violated_policies || [];
      return findings.map((finding) => {
        const moduleName = normalizeUnknown(finding.Matches || extractModuleName(finding.description));
        return [moduleName, normalizeSeverity(finding.severity, "Medium")];
      });
    })
  );
  const dependencyData = latestScan?.scan_results?.scan_results?.scanner_results?.sbom?.metadata?.dependencies;
  if (Array.isArray(dependencyData) && dependencyData.length > 0) {
    return dependencyData.map((dep) => {
      const moduleName = getDependencyName(dep);
      const moduleKey = toModuleKey(moduleName);
      const resolvedCveId = resolveCveId(
        dep,
        dep?.description,
        cveByModule.get(moduleKey) || ""
      );
      const resolvedSeverity = resolveDependencySeverity(
        dep,
        severityByModule.get(moduleName),
        "Medium"
      );
      const resolvedOssRisk = resolveDependencyOssRisk(
        dep,
        ossRiskByModule.get(moduleKey)
      );
      const selectedVuln = findVulnerabilityById(dep?.vulnerabilities, resolvedCveId);

      return {
        moduleName,
        versionInfo: getDependencyVersion(dep),
        licenseConcluded: getDependencyLicense(dep),
        packageManager: getDependencyPackageManager(dep),
        packageURL: getDependencyPackageUrl(dep),
        cveId: resolvedCveId,
        vulnCount: Array.isArray(dep?.vulnerabilities) ? dep.vulnerabilities.length : 0,
        sourceLocation: getDependencySourceLocation(dep),
        codeBlock: dep?.codeBlock || dep?.code_block || dep?.sourceContext || dep?.source_context || "",
        severity: resolvedSeverity,
        ossRisk: resolvedOssRisk,
        description: selectedVuln?.description || dep?.description || "",
        cvssScore: selectedVuln?.cvss_score ?? "N/A",
        epssScore: selectedVuln?.epss_score !== undefined && selectedVuln?.epss_score !== null
          ? asPercentFromFraction(selectedVuln?.epss_score)
          : "N/A",
        kev: asKevText(selectedVuln?.kev),
        cweIds: Array.isArray(selectedVuln?.cwe_ids) ? selectedVuln.cwe_ids : [],
        reachability: selectedVuln?.reachability || "Unknown",
        published: asDateText(selectedVuln?.published, "Unknown"),
        affectedVersion:
          selectedVuln?.affectedVersion ??
          selectedVuln?.affectedVersions ??
          selectedVuln?.affected_version ??
          selectedVuln?.affected_range ??
          selectedVuln?.affectedRange ??
          selectedVuln?.vulnerableVersion ??
          selectedVuln?.vulnerableVersions ??
          selectedVuln?.vulnerable_version ??
          selectedVuln?.vulnerable_versions ??
          selectedVuln?.versionRange ??
          selectedVuln?.version_range ??
          selectedVuln?.affected ??
          dep?.affectedVersion ??
          dep?.affectedVersions ??
          dep?.affected_version ??
          dep?.affected_range ??
          dep?.affectedRange ??
          dep?.vulnerableVersion ??
          dep?.vulnerableVersions ??
          dep?.vulnerable_version ??
          dep?.vulnerable_versions ??
          dep?.versionRange ??
          dep?.version_range ??
          dep?.affected ??
          "",
        fixedVersion:
          selectedVuln?.fixedVersion ??
          selectedVuln?.fixed_version ??
          selectedVuln?.fixVersion ??
          selectedVuln?.fix_version ??
          selectedVuln?.patchedVersion ??
          selectedVuln?.patched_version ??
          selectedVuln?.firstPatchedVersion ??
          selectedVuln?.first_patched_version ??
          dep?.fixedVersion ??
          dep?.fixed_version ??
          dep?.fixVersion ??
          dep?.fix_version ??
          dep?.patchedVersion ??
          dep?.patched_version ??
          dep?.firstPatchedVersion ??
          dep?.first_patched_version ??
          "",
        patched:
          selectedVuln?.patched ??
          selectedVuln?.patchedVersion ??
          selectedVuln?.patched_version ??
          selectedVuln?.firstPatchedVersion ??
          selectedVuln?.first_patched_version ??
          selectedVuln?.fix_version ??
          dep?.patched ??
          dep?.patchedVersion ??
          dep?.patched_version ??
          dep?.firstPatchedVersion ??
          dep?.first_patched_version ??
          dep?.fix_version ??
          ""
      };
    });
  }
  if (!Array.isArray(sbomResults) || sbomResults.length === 0) return [];
  return sbomResults.flatMap((result) => {
    const packages = result.violated_policies || [];
    return packages.map((pkg) => ({
      moduleName: normalizeUnknown(pkg.Matches || extractModuleName(pkg.description)),
      versionInfo: normalizeUnknown(extractVersion(pkg.description)),
      licenseConcluded: normalizeUnknown(extractLicense(pkg.description)),
      packageManager: normalizeUnknown(extractPackageManager(pkg.description)),
      packageURL: normalizePackageUrl(pkg.remediation),
      cveId: resolveCveId(
        pkg,
        pkg.description,
        cveByModule.get(toModuleKey(pkg.Matches || extractModuleName(pkg.description))) || ""
      ),
      vulnCount: 0,
      sourceLocation: normalizeUnknown(result.file_name, ""),
      codeBlock: pkg.codeBlock || pkg.code_block || pkg.sourceContext || pkg.source_context || "",
      severity: normalizeSeverity(pkg.severity, "Medium"),
      ossRisk: normalizeOssRisk(pkg?.oss_risk, "")
    }));
  });
}

export function getSbomScanner(latestScan) {
  return latestScan?.scan_results?.scan_results?.scanner_results?.sbom || null;
}

export function getMetadataCards(scanMetadata) {
  return [
    {
      label: "Last Commit",
      value: scanMetadata.repository || scanMetadata.repo_name || "N/A",
      icon: GitCommitHorizontal,
    },
    {
      label: "Commit Author",
      value: String(scanMetadata.commit_author ?? scanMetadata.author ?? "").trim() || "N/A",
      icon: User,
    },
    {
      label: "Commit",
      value: scanMetadata.commit_message || "N/A",
      icon: GitCompare,
    },
    {
      label: "Scan Date",
      value: formatDate(scanMetadata.scan_timestamp || scanMetadata.created_at),
      icon: Calendar,
    },
  ];
}

export function getChartColors() {
  return {
    primary: 'var(--color-primary)',
    secondary: 'var(--color-secondary)',
    accent: 'var(--color-accent)',
    success: 'var(--success)',
    danger: 'var(--danger)',
    warning: 'var(--warning)',
    info: 'var(--info)',
    muted: 'var(--muted)'
  };
}

export function getChartSeries(chartColors) {
  return [
    chartColors.primary,
    chartColors.secondary,
    chartColors.accent,
    chartColors.success,
    chartColors.danger,
    chartColors.warning,
    chartColors.info
  ];
}

export function getUniqueLicenses(packages, sbomScanner) {
  const fromMetadata = sbomScanner?.metadata?.licenses;
  if (Array.isArray(fromMetadata) && fromMetadata.length > 0) return [...fromMetadata].sort();
  return [...new Set(packages.map((p) => p.licenseConcluded).filter(Boolean))].sort();
}

export function getUniquePackageManagers(packages, sbomScanner) {
  const fromMetadata = sbomScanner?.metadata?.package_managers;
  if (Array.isArray(fromMetadata) && fromMetadata.length > 0) return [...fromMetadata].sort();
  return [...new Set(packages.map((p) => p.packageManager).filter(Boolean))].sort();
}

export function getUniqueLanguages(packages) {
  return [...new Set(packages.map(p => p.packageManager).filter(Boolean))];
}

export function getUniqueRiskLevels(packages) {
  const riskLevels = [...new Set(packages.map(pkg => getDisplayRiskLevel(pkg)))];
  return riskLevels.sort();
}

export function getUniqueApprovalStatuses(packages) {
  const statuses = [...new Set(packages.map(pkg => {
    const licenseInfo = getLicenseInfo(pkg.licenseConcluded);
    return licenseInfo.approvalStatus;
  }))];
  return statuses.sort();
}

export function getComplianceStats(packages, sbomScanner) {
  const unknownFromMeta = sbomScanner?.metadata?.unknown_licenses_count;
  const stats = {
    total: sbomScanner?.metadata?.total_packages ?? packages.length,
    preApproved: 0,
    reviewRequired: 0,
    legalReviewRequired: 0,
    highRisk: 0,
    mediumRisk: 0,
    lowRisk: 0,
    unknown: unknownFromMeta ?? 0,
  };
  packages.forEach(pkg => {
    const licenseInfo = getLicenseInfo(pkg.licenseConcluded);
    const displayRiskLevel = getDisplayRiskLevel(pkg);
    if (unknownFromMeta === undefined && (!pkg.licenseConcluded || pkg.licenseConcluded === "Unknown")) {
      stats.unknown++;
    }
    switch (licenseInfo.approvalStatus) {
      case 'Pre-approved':
        stats.preApproved++;
        break;
      case 'Review-Required':
        stats.reviewRequired++;
        break;
      case 'Legal-Review-Required':
      case 'Purchase-Legal-Review':
      case 'Legal-IT-Approval':
        stats.legalReviewRequired++;
        break;
    }
    switch (displayRiskLevel) {
      case 'Low':
        stats.lowRisk++;
        break;
      case 'Medium':
        stats.mediumRisk++;
        break;
      case 'Critical':
      case 'High':
        stats.highRisk++;
        break;
    }
  });
  return stats;
}

export function getSummaryCards(sbomScanner, packages, uniqueLicenses, uniquePackageManagers, complianceStats) {
  return [
    {
      title: "Total Packages",
      value: sbomScanner?.metadata?.total_packages ?? packages.length,
      color: "#3B82F6",
      icon: Package,
    },
    {
      title: "License Types",
      value: sbomScanner?.metadata?.unique_license_types ?? uniqueLicenses.length,
      color: "#8B5CF6",
      icon: Layers,
    },
    {
      title: "Unknown Licenses",
      value: complianceStats.unknown,
      color: "#F59E0B",
      icon: ShieldAlert,
    },
    {
      title: "Package Managers",
      value: sbomScanner?.metadata?.total_package_managers ?? uniquePackageManagers.length,
      color: "#06B6D4",
      icon: Settings,
    },
  ];
}

export function getChartData(packages, complianceStats, CHART_SERIES) {
  const getLicenseInfo = (licenseConcluded) => {
    if (!licenseConcluded || licenseConcluded === "UNKNOWN" || licenseConcluded === "Unknown") {
      return LICENSE_POLICY_MAP.NOASSERTION || {
        category: "Unknown",
        riskLevel: "High",
        approvalStatus: "Legal-Review-Required",
        usageRules: "License not declared - requires manual review and legal assessment"
      };
    }
    const riskOrder = { 'High': 3, 'Medium': 2, 'Low': 1, 'Variable': 2 };
    if (licenseConcluded.includes(' AND ')) {
      const licenses = licenseConcluded.split(' AND ');
      const licenseInfos = licenses.map(license => LICENSE_POLICY_MAP[resolveLicenseKey(license.trim())]).filter(Boolean);
      if (licenseInfos.length === 0) return LICENSE_POLICY_MAP.NOASSERTION;
      return licenseInfos.sort((a, b) => riskOrder[b.riskLevel] - riskOrder[a.riskLevel])[0];
    }
    if (licenseConcluded.includes(' OR ')) {
      const licenses = licenseConcluded.split(' OR ');
      const licenseInfos = licenses.map(license => LICENSE_POLICY_MAP[resolveLicenseKey(license.trim())]).filter(Boolean);
      if (licenseInfos.length === 0) return LICENSE_POLICY_MAP.NOASSERTION;
      return licenseInfos.sort((a, b) => riskOrder[a.riskLevel] - riskOrder[b.riskLevel])[0];
    }
    return LICENSE_POLICY_MAP[resolveLicenseKey(licenseConcluded)] || LICENSE_POLICY_MAP.NOASSERTION || {
      category: "Unknown",
      riskLevel: "High",
      approvalStatus: "Legal-Review-Required",
      usageRules: "License not declared - requires manual review and legal assessment"
    };
  };
  const riskDistributionData = [
    { name: 'Low Risk', value: complianceStats.lowRisk, color: 'var(--success)' },
    { name: 'Medium Risk', value: complianceStats.mediumRisk, color: 'var(--warning)' },
    { name: 'High Risk', value: complianceStats.highRisk, color: 'var(--danger)' },
    { name: 'Unknown', value: complianceStats.unknown, color: 'var(--muted)' }
  ];
  const approvalStatusData = [
    { name: 'Pre-approved', value: complianceStats.preApproved, color: 'var(--success)' },
    { name: 'Review Required', value: complianceStats.reviewRequired, color: 'var(--warning)' },
    { name: 'Legal Review', value: complianceStats.legalReviewRequired, color: 'var(--danger)' }
  ];
  const licenseTypeData = packages.reduce((acc, pkg) => {
    const licenseInfo = getLicenseInfo(pkg.licenseConcluded);
    const category = licenseInfo.category || 'Unknown';
    acc[category] = (acc[category] || 0) + 1;
    return acc;
  }, {});
  const licenseTypeChartData = Object.entries(licenseTypeData).map(([name, value], index) => ({
    name,
    value,
    color: CHART_SERIES[index % CHART_SERIES.length]
  }));
  const packageManagerData = packages.reduce((acc, pkg) => {
    const manager = pkg.packageManager || 'Unknown';
    acc[manager] = (acc[manager] || 0) + 1;
    return acc;
  }, {});
  const packageManagerChartData = Object.entries(packageManagerData)
    .sort(([, a], [, b]) => b - a)
    .slice(0, 8)
    .map(([name, value], index) => ({
      name,
      value,
      color: CHART_SERIES[index % CHART_SERIES.length]
    }));
  return {
    riskDistribution: riskDistributionData.filter(item => item.value > 0),
    approvalStatus: approvalStatusData.filter(item => item.value > 0),
    licenseTypes: licenseTypeChartData.filter(item => item.value > 0),
    packageManagers: packageManagerChartData
  };
}

export function getFilteredAndSortedPackages(packages, searchTerm, licenseFilter, packageManagerFilter, languageFilter, riskLevelFilter, approvalStatusFilter, sortConfig) {
  const getLicenseInfo = (licenseConcluded) => {
    if (!licenseConcluded || licenseConcluded === "UNKNOWN" || licenseConcluded === "Unknown") {
      return LICENSE_POLICY_MAP.NOASSERTION || {
        category: "Unknown",
        riskLevel: "High",
        approvalStatus: "Legal-Review-Required",
        usageRules: "License not declared - requires manual review and legal assessment"
      };
    }
    const riskOrder = { 'High': 3, 'Medium': 2, 'Low': 1, 'Variable': 2 };
    if (licenseConcluded.includes(' AND ')) {
      const licenses = licenseConcluded.split(' AND ');
      const licenseInfos = licenses.map(license => LICENSE_POLICY_MAP[resolveLicenseKey(license.trim())]).filter(Boolean);
      if (licenseInfos.length === 0) return LICENSE_POLICY_MAP.NOASSERTION;
      return licenseInfos.sort((a, b) => riskOrder[b.riskLevel] - riskOrder[a.riskLevel])[0];
    }
    if (licenseConcluded.includes(' OR ')) {
      const licenses = licenseConcluded.split(' OR ');
      const licenseInfos = licenses.map(license => LICENSE_POLICY_MAP[resolveLicenseKey(license.trim())]).filter(Boolean);
      if (licenseInfos.length === 0) return LICENSE_POLICY_MAP.NOASSERTION;
      return licenseInfos.sort((a, b) => riskOrder[a.riskLevel] - riskOrder[b.riskLevel])[0];
    }
    return LICENSE_POLICY_MAP[resolveLicenseKey(licenseConcluded)] || LICENSE_POLICY_MAP.NOASSERTION || {
      category: "Unknown",
      riskLevel: "High",
      approvalStatus: "Legal-Review-Required",
      usageRules: "License not declared - requires manual review and legal assessment"
    };
  };
  const getDisplayRiskLevel = (pkg) => {
    const severityRisk = pkg?.severity;
    if (severityRisk) return severityRisk;
    return getLicenseInfo(pkg?.licenseConcluded).riskLevel;
  };
  let filtered = packages.filter((pkg) => {
    const matchesSearch =
      pkg.moduleName?.toLowerCase().includes(searchTerm.toLowerCase()) ||
      pkg.versionInfo?.toLowerCase().includes(searchTerm.toLowerCase()) ||
      pkg.packageURL?.toLowerCase().includes(searchTerm.toLowerCase()) ||
      pkg.cveId?.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesLicense =
      licenseFilter === "all" ||
      (licenseFilter === "Unknown"
        ? (!pkg.licenseConcluded || pkg.licenseConcluded === "Unknown")
        : pkg.licenseConcluded === licenseFilter);
    const matchesPackageManager =
      packageManagerFilter === "all" ||
      pkg.packageManager === packageManagerFilter;
    const matchesLanguage = languageFilter === "all" ||
      pkg.packageManager === languageFilter;
    const licenseInfo = getLicenseInfo(pkg.licenseConcluded);
    const matchesRiskLevel = riskLevelFilter === "all" || getDisplayRiskLevel(pkg) === riskLevelFilter;
    const matchesApprovalStatus = approvalStatusFilter === "all" || licenseInfo.approvalStatus === approvalStatusFilter;
    return matchesSearch && matchesLicense && matchesPackageManager && matchesLanguage && matchesRiskLevel && matchesApprovalStatus;
  });
  if (sortConfig.key) {
    filtered.sort((a, b) => {
      let aVal = a[sortConfig.key] || '';
      let bVal = b[sortConfig.key] || '';
      if (sortConfig.key === 'riskLevel' || sortConfig.key === 'approvalStatus') {
        const aLicenseInfo = getLicenseInfo(a.licenseConcluded);
        const bLicenseInfo = getLicenseInfo(b.licenseConcluded);
        aVal = sortConfig.key === 'riskLevel' ? getDisplayRiskLevel(a) : aLicenseInfo.approvalStatus;
        bVal = sortConfig.key === 'riskLevel' ? getDisplayRiskLevel(b) : bLicenseInfo.approvalStatus;
      }
      if (aVal < bVal) {
        return sortConfig.direction === "asc" ? -1 : 1;
      }
      if (aVal > bVal) {
        return sortConfig.direction === "asc" ? 1 : -1;
      }
      return 0;
    });
  }
  return filtered;
}

export function getScoreColor(score) {
  if (score >= 90) return "#22C55E";
  if (score >= 70) return "#F59E0B";
  return "#EF4444";
}

export function getLicenseInfo(licenseConcluded) {
  if (!licenseConcluded || licenseConcluded === "UNKNOWN" || licenseConcluded === "Unknown") {
    return LICENSE_POLICY_MAP.NOASSERTION || {
      category: "Unknown",
      riskLevel: "High",
      approvalStatus: "Legal-Review-Required",
      usageRules: "License not declared - requires manual review and legal assessment"
    };
  }
  const riskOrder = { 'High': 3, 'Medium': 2, 'Low': 1, 'Variable': 2 };
  if (licenseConcluded.includes(' AND ')) {
    // Conjunctive: every listed license applies, so the combined obligation is the worst case.
    const licenses = licenseConcluded.split(' AND ');
    const licenseInfos = licenses.map(license => LICENSE_POLICY_MAP[resolveLicenseKey(license.trim())]).filter(Boolean);
    if (licenseInfos.length === 0) return LICENSE_POLICY_MAP.NOASSERTION;
    return licenseInfos.sort((a, b) => riskOrder[b.riskLevel] - riskOrder[a.riskLevel])[0];
  }
  if (licenseConcluded.includes(' OR ')) {
    // Disjunctive: the licensee may choose whichever license they prefer, so the real risk is the best case.
    const licenses = licenseConcluded.split(' OR ');
    const licenseInfos = licenses.map(license => LICENSE_POLICY_MAP[resolveLicenseKey(license.trim())]).filter(Boolean);
    if (licenseInfos.length === 0) return LICENSE_POLICY_MAP.NOASSERTION;
    return licenseInfos.sort((a, b) => riskOrder[a.riskLevel] - riskOrder[b.riskLevel])[0];
  }
  return LICENSE_POLICY_MAP[resolveLicenseKey(licenseConcluded)] || LICENSE_POLICY_MAP.NOASSERTION || {
    category: "Unknown",
    riskLevel: "High",
    approvalStatus: "Legal-Review-Required",
    usageRules: "License not declared - requires manual review and legal assessment"
  };
}

export function getDisplayRiskLevel(pkg) {
  return getLicenseInfo(pkg?.licenseConcluded).riskLevel;
}
// Placeholder for SBOM utility functions
// Move shared helper functions here as needed

export const toFiniteNumber = (value, fallback = 0) => {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
};

export const formatDate = (dateString) => {
  if (!dateString) return "N/A";
  const date = new Date(dateString);
  if (Number.isNaN(date.getTime())) return "N/A";
  return date.toLocaleDateString();
};

export const formatDateTime = (dateString) => {
  if (!dateString) return "N/A";
  const date = new Date(dateString);
  if (Number.isNaN(date.getTime())) return "N/A";
  return date.toLocaleString(undefined, {
    day: "2-digit",
    month: "long",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
};
