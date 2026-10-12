import Link from "next/link";
import { ArrowLeft } from "lucide-react";
import styles from "./CveDetailPage.module.css";
import CveAutofixActions from "./CveAutofixActions";

const KNOWN_REPORTS = {
    "CVE-2022-24999": {
        packageName: "Express",
        packageVersion: "4.17.21",
        ecosystem: "npm",
        ossRisk: "Critical",
        cveId: "CVE-2022-24999",
        cvssScore: "6.5",
        riskPriority: "Medium",
        epssScore: "0.90%",
        kev: "Yes",
        cweIds: ["CWE-601"],
        reachability: "Not Reachable",
        affected: "< 4.18.2",
        patched: "4.18.2",
        published: "12-12-2017",
        lastUpdated: "30-06-2023",
        description:
            "qs and express are vulnerable to an open redirect attack when using a malformed URL. The qs module used by express did not properly sanitize certain request parameters, allowing crafted URLs to redirect users to arbitrary destinations.",
    },
};

const CWE_FALLBACK = ["CWE-601"];

export function getString(value, fallback = "") {
    if (Array.isArray(value)) {
        const first = value.find((item) => String(item || "").trim());
        if (first !== undefined) {
            const parsedArrayValue = String(first).trim();
            return parsedArrayValue || fallback;
        }
        return fallback;
    }
    const parsed = String(value || "").trim();
    return parsed || fallback;
}

export function getParam(searchParams, keys, fallback = "") {
    for (const key of keys) {
        const value = getString(searchParams?.[key], "");
        if (value) return value;
    }
    return fallback;
}

export function normalizeReachability(value) {
    const raw = getString(value, "");
    if (!raw) return "Unknown";
    const normalized = raw.replace(/[-_]+/g, " ").trim().toLowerCase();
    if (!normalized) return "Unknown";
    return normalized
        .split(" ")
        .filter(Boolean)
        .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
        .join(" ");
}

export function normalizeCweIds(raw) {
    if (!raw) return [];
    if (Array.isArray(raw)) return raw.filter(Boolean);
    return String(raw)
        .split(",")
        .map((item) => item.trim())
        .filter(Boolean);
}

export function isPlaceholderValue(value) {
    const raw = getString(value, "").trim().toLowerCase();
    return !raw || raw === "unknown" || raw === "n/a" || raw === "na" || raw === "-" || raw === "null" || raw === "undefined";
}

export function extractAffectedFromDescription(description) {
    const text = getString(description, "");
    if (!text) return "";

    const normalizedText = text
        .replace(/&lt;/gi, "<")
        .replace(/&gt;/gi, ">")
        .replace(/&le;/gi, "<=")
        .replace(/&ge;/gi, ">=")
        .replace(/≤/g, "<=")
        .replace(/≥/g, ">=")
        .replace(/<\s+=/g, "<=")
        .replace(/>\s+=/g, ">=");

    // Capture explicit comparator expressions directly from advisory text.
    const rangeMatch = normalizedText.match(/([<>!]=?|=)\s*v?\d+(?:\.\d+){0,4}(?:[-+][0-9A-Za-z.-]+)?(?:\s*,\s*([<>!]=?|=)\s*v?\d+(?:\.\d+){0,4}(?:[-+][0-9A-Za-z.-]+)?)?/i);
    if (rangeMatch?.[0]) return rangeMatch[0].trim();

    const priorToMatch = normalizedText.match(/(?:prior to|before)\s+v?(\d+(?:\.\d+){0,4}(?:[-+][0-9A-Za-z.-]+)?)/i);
    if (priorToMatch?.[1]) return `< ${priorToMatch[1]}`;

    const throughMatch = normalizedText.match(/(?:through|up to and including|up to)\s+v?(\d+(?:\.\d+){0,4}(?:[-+][0-9A-Za-z.-]+)?)/i);
    if (throughMatch?.[1]) return `<= ${throughMatch[1]}`;

    return "";
}

export function extractPatchedFromDescription(description) {
    const text = getString(description, "");
    if (!text) return "";

    const normalizedText = text
        .replace(/&lt;/gi, "<")
        .replace(/&gt;/gi, ">")
        .replace(/&le;/gi, "<=")
        .replace(/&ge;/gi, ">=")
        .replace(/≤/g, "<=")
        .replace(/≥/g, ">=");

    const fixedMatch = normalizedText.match(/(?:fixed|patched|resolved)\s+(?:in|by|starting in)\s+v?(\d+(?:\.\d+){0,4}(?:[-+][0-9A-Za-z.-]+)?)/i);
    if (fixedMatch?.[1]) return fixedMatch[1];

    const priorToMatch = normalizedText.match(/(?:prior to|before)\s+v?(\d+(?:\.\d+){0,4}(?:[-+][0-9A-Za-z.-]+)?)/i);
    if (priorToMatch?.[1]) return priorToMatch[1];

    return "";
}

export function resolveAffectedValue(searchParams) {
    const explicitAffectedVersion = getParam(
        searchParams,
        [
            "affectedVersion",
            "affectedVersions",
            "affected_version",
            "affectedRange",
            "affected_range",
            "vulnerableVersion",
            "vulnerableVersions",
            "vulnerable_version",
            "vulnerable_versions",
            "versionRange",
            "version_range",
            "vulnerableRange",
            "vulnerable_range",
        ],
        ""
    );
    if (explicitAffectedVersion && !isPlaceholderValue(explicitAffectedVersion)) return explicitAffectedVersion;

    const explicitAffected = getParam(searchParams, ["affected"], "");
    if (explicitAffected && !isPlaceholderValue(explicitAffected)) return explicitAffected;

    const fromDescription = extractAffectedFromDescription(
        getParam(searchParams, ["description", "desc", "details"], "")
    );
    if (fromDescription) return fromDescription;

    return "Unknown";
}

export function resolvePatchedValue(searchParams) {
    const explicitFixedVersion = getParam(
        searchParams,
        [
            "fixedVersion",
            "fixed_version",
            "fixVersion",
            "fix_version",
            "patchedVersion",
            "patched_version",
            "firstPatchedVersion",
            "first_patched_version",
        ],
        ""
    );
    if (explicitFixedVersion && !isPlaceholderValue(explicitFixedVersion)) return explicitFixedVersion;

    const explicitPatched = getParam(searchParams, ["patched", "patch"], "");
    if (explicitPatched && !isPlaceholderValue(explicitPatched)) return explicitPatched;

    const fromDescription = extractPatchedFromDescription(
        getParam(searchParams, ["description", "desc", "details"], "")
    );
    if (fromDescription) return fromDescription;

    return "Unknown";
}

export function resolveReport(rawCveId, searchParams) {
    const cveFromParams = getParam(searchParams, ["cve", "cveId", "cve_id", "id"], "");
    const normalizedCve = getString(rawCveId || cveFromParams).toUpperCase();
    const known = KNOWN_REPORTS[normalizedCve] || {};
    const packageName = getParam(searchParams, ["pkg", "package", "packageName", "moduleName", "name"], known.packageName || "Unknown package");
    const packageVersion = getParam(searchParams, ["version", "versionInfo", "pkgVersion", "packageVersion"], "Unknown");
    const cweRaw = getParam(searchParams, ["cwe", "cweIds", "cwe_ids"], "");
    const cweIds = normalizeCweIds(cweRaw || known.cweIds || []);
    const severity = getParam(searchParams, ["severity", "risk", "riskLevel"], "");
    const riskPriority = getParam(searchParams, ["priority", "riskPriority"], severity || known.riskPriority || "Medium");
    const description = getParam(searchParams, ["description", "desc", "details"], known.description || "No description available.");
    const affected = resolveAffectedValue(searchParams);
    const patched = resolvePatchedValue(searchParams);

    const titleText = getString(
        searchParams?.title,
        `${riskPriority} CVE: ${packageName.toLowerCase()}: Open Redirect via malformed URL`
    );

    return {
        packageName,
        packageVersion,
        ecosystem: getParam(searchParams, ["ecosystem", "packageManager", "manager"], known.ecosystem || "npm"),
        ossRisk: getParam(searchParams, ["ossRisk", "oss_risk", "ossrisk"], severity || known.ossRisk || "Unknown"),
        cveId: normalizedCve || known.cveId || "Unknown CVE",
        cvssScore: getParam(searchParams, ["cvss", "cvssScore", "cvss_score"], known.cvssScore || "N/A"),
        riskPriority,
        epssScore: getParam(searchParams, ["epss", "epssScore", "epss_score"], known.epssScore || "N/A"),
        kev: getParam(searchParams, ["kev", "knownExploited"], known.kev || "Unknown"),
        cweIds: cweIds.length > 0 ? cweIds : CWE_FALLBACK,
        reachability: normalizeReachability(getParam(searchParams, ["reachability", "reachable"], known.reachability || "Unknown")),
        affected,
        patched,
        published: getParam(searchParams, ["published", "publishedAt"], known.published || "Unknown"),
        lastUpdated: getParam(searchParams, ["updated", "lastUpdated", "modifiedAt"], known.lastUpdated || "Unknown"),
        description,
        file: getParam(searchParams, ["file", "sourceFile", "source_file"], ""),
        codeBlock: getParam(searchParams, ["codeBlock", "code_block", "sourceContext"], ""),
        titleText,
    };
}

function DetailRow({ label, value, valueClassName = "" }) {
    return (
        <div className={styles.detailRow}>
            <div className={styles.labelCell}>{label}</div>
            <div className={styles.valueCell}>
                <span className={`${styles.valueText} ${valueClassName}`.trim()}>{value}</span>
            </div>
        </div>
    );
}

export default async function CveDetailsPage({ params, searchParams }) {
    const resolvedParams = await Promise.resolve(params || {});
    const resolvedSearchParams = await Promise.resolve(searchParams || {});
    const report = resolveReport(resolvedParams?.cveId, resolvedSearchParams);
    const versionBadge = report.packageVersion.toLowerCase().startsWith("v")
        ? report.packageVersion
        : `v${report.packageVersion}`;
    const isCritical = report.ossRisk.toLowerCase() === "critical";
    const titleToneClass = isCritical ? styles.titleCritical : styles.titleDefault;

    return (
        <main className={`${styles.pageRoot} bg-[var(--card-bg)]`}>
            <section className={styles.sbomPage}>
                <div className={styles.shellCard}>
                    <header className={styles.topContainer}>
                        <div className={styles.pkgGroup}>
                            <Link href="/scanops/sbom" className={styles.backBtn} aria-label="Back to SBOM">
                                <ArrowLeft size={14} />
                            </Link>
                            <div className={styles.pkgMeta}>
                                <div className={styles.pkgTitleRow}>
                                    <h1 className={styles.pkgTitle}>{report.packageName}</h1>
                                    <span className={styles.versionPill}>{versionBadge}</span>
                                </div>
                                <p className={styles.pkgSubtitle}>CVE Vulnerability Report</p>
                            </div>
                        </div>
                        <div className={styles.actionWrap}>
                            <CveAutofixActions report={report} />
                        </div>
                    </header>

                    <section className={styles.cveDetailWrap}>
                        <div className={styles.cveCard}>
                            <div className={styles.cardHead}>
                                <h2 className={`${styles.vulnTitle} ${titleToneClass}`}>{report.titleText}</h2>
                                <div className={styles.metaRow}>
                                    <div className={styles.metaItem}>
                                        <span className={styles.metaLabel}>Ecosystem :</span>
                                        <span className={styles.metaValue}>{report.ecosystem}</span>
                                    </div>
                                    <div className={styles.metaItem}>
                                        <span className={styles.metaLabel}>OSS Risk:</span>
                                        <span className={isCritical ? styles.metaCritical : styles.metaValue}>{report.ossRisk}</span>
                                    </div>
                                </div>
                            </div>

                            <div className={styles.detailsSection}>
                                <p className={styles.detailsTitle}>Details</p>
                                <div className={styles.detailsBox}>
                                    <DetailRow
                                        label="CVE ID"
                                        value={report.cveId}
                                        valueClassName={styles.linkishValue}
                                    />
                                    <DetailRow label="CVSS Score" value={report.cvssScore} />
                                    <DetailRow label="Risk Priority" value={report.riskPriority} valueClassName={styles.linkishValue} />
                                    <DetailRow label="EPSS Score" value={report.epssScore} />
                                    <DetailRow label="KEV" value={report.kev} />
                                    <DetailRow label="CWE IDs" value={report.cweIds.join(", ")} />
                                    <DetailRow label="Reachability" value={report.reachability} valueClassName={styles.reachabilityValue} />
                                    <DetailRow label="Affected" value={report.affected} />
                                    <DetailRow label="Patched" value={report.patched} valueClassName={styles.patchedValue} />
                                    <DetailRow label="Published" value={report.published} />
                                    <DetailRow label="Last Updated" value={report.lastUpdated} />
                                </div>
                            </div>

                            <div className={styles.descriptionSection}>
                                <p className={styles.detailsTitle}>Description</p>
                                <p className={styles.descriptionText}>{report.description}</p>
                            </div>
                        </div>
                    </section>
                </div>
            </section>
        </main>
    );
}