/**
 * formatApiText — Convert any raw API string to readable Title Case.
 * Handles underscores, hyphens, spaces, and mixed-case input.
 *
 * Examples:
 *  "pull_request"   → "Pull Request"
 *  "yaml-json"      → "Yaml Json"
 *  "FULL_SCAN"      → "Full Scan"
 *  ""  / null / undefined → "N/A"
 */
export const formatApiText = (value) => {
    const raw = String(value ?? "").trim();
    if (!raw) return "N/A";
    if (raw.toUpperCase() === "N/A") return "N/A";

    // Convert camelCase/PascalCase tokens to spaced words before normalization.
    const withWordBreaks = raw
        .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
        .replace(/([A-Z]+)([A-Z][a-z])/g, "$1 $2");

    const parts = withWordBreaks
        .replace(/[^a-zA-Z0-9\s_-]/g, " ")
        .split(/[\s_-]+/)
        .filter(Boolean)
        .map((part) => part.toLowerCase());

    if (!parts.length) return "N/A";

    const tokenMap = {
        api: "API",
        aws: "AWS",
        ci: "CI",
        cis: "CIS",
        cd: "CD",
        eol: "EOL",
        gcp: "GCP",
        iac: "INFRASTRUCTURE AS CODE",
        id: "ID",
        json: "JSON",
        oauth: "OAuth",
        oss: "OSS",
        sbom: "SBOM",
        url: "URL",
        yaml: "YAML",
        github: "GitHub",
        nodejs: "Node.js",
    };

    return parts
        .map((part) => tokenMap[part] || (part.charAt(0).toUpperCase() + part.slice(1)))
        .join(" ");
};
