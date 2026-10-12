// utils.js
export const COLORS = {
  // Workflow and technology colors
  workflow: "var(--color-primary)",
  docker: "var(--color-secondary)",
  dockerfile: "var(--color-secondary)",
  container: "var(--color-secondary)",
  kubernetes: "var(--color-accent)",
  uberneetess: "var(--color-accent)",
  uberneetes: "var(--color-accent)",
  k8s: "var(--color-accent)",

  // Severity colors
  critical: "var(--danger)",
  high: "var(--warning)",
  medium: "var(--color-primary-600)",
  low: "var(--muted)",
  info: "var(--info)",

  // Status colors
  success: "var(--success)",
  danger: "var(--danger)",
  warning: "var(--warning)",

  // Primary colors
  primary: "var(--color-primary)",
  secondary: "var(--color-secondary)",
  accent: "var(--color-accent)",

  // Background and surface
  background: "var(--bg)",
  surface: "var(--surface)",
  elevated: "var(--elevated-surface)",

  // Text and border
  text: "var(--text)",
  muted: "var(--muted)",
  border: "var(--border)",

  // Additional subscan types (if needed)
  secret: "var(--color-accent)",
  code: "var(--color-primary)",
  dependency: "var(--color-secondary)",
  infrastructure: "var(--info)",
  container: "var(--color-secondary)",
  sbom: "var(--success)",
  yara: "var(--danger)",
  "spec-scanner": "var(--info)",
  "spec-scanner-findings": "var(--info)",
  sast: "var(--color-primary)",
  dast: "var(--color-secondary)",
  sca: "var(--color-accent)",
};

// Helper function to get color by key with fallback
export const getColor = (key) => {
  if (!key) return COLORS.info;

  const normalizedKey = key.toLowerCase();
  return COLORS[normalizedKey] || COLORS.info;
};

// Capitalize helper
export const capitalize = (str) => {
  if (!str || typeof str !== 'string') return "";
  return str.charAt(0).toUpperCase() + str.slice(1);
};

// Normalize API text values into readable Title Case labels
// Canonical implementation lives in shared/textUtils.js — re-exported here for backwards compat.
export { formatApiText } from "../shared/textUtils";

// Map scanner keys to product-specific display labels.
export const formatScannerDisplayName = (scannerKey) => {
  const normalized = String(scannerKey || "")
    .trim()
    .toLowerCase()
    .replace(/\s+/g, "_")
    .replace(/-/g, "_");

  if (normalized === "yaml_json") return "CODE LINTER";
  if (normalized === "yara") return "CODE QUALITY";
  if (normalized === "sbom") return "SBOM";
  if (normalized === "iac") return "INFRASTRUCTURE AS CODE";
  if (normalized === "github_actions" || normalized === "workflow") return "GITHUB ACTIONS WORKFLOW";
  if (normalized === "secret_scanner" || normalized === "secret") return "SECRET SCANNER";
  if (normalized === "spec_scanner") return "API DISCOVERY";
  if (normalized === "docker" || normalized === "dockerfile" || normalized === "container") return "DOCKER";
  if (normalized === "cis" || normalized === "cis_agent" || normalized === "cis-agent" || normalized === "_cis_agent") return "CIS AGENT";
  if (
    normalized === "kubernetes" ||
    normalized === "k8s" ||
    normalized === "uberneetess" ||
    normalized === "uberneetes"
  ) {
    return "KUBERNETES";
  }
  if (normalized === "skill_scanner" || normalized === "skill-scanner" || normalized === "ai_security_scanner") {
    return "AI SECURITY SCANNER";
  }

  return normalized
    ? normalized
      .split("_")
      .filter(Boolean)
      .map((part) => {
        if (part === "cis") return "CIS";
        if (part === "iac") return "INFRASTRUCTURE AS CODE";
        if (part === "sbom") return "SBOM";
        if (part === "api") return "API";
        if (part === "aws") return "AWS";
        if (part === "gcp") return "GCP";
        if (part === "oauth") return "OAuth";
        if (part === "github") return "GitHub";
        if (part === "yaml") return "YAML";
        if (part === "json") return "JSON";
        if (part === "oss") return "OSS";
        if (part === "k8s") return "KUBERNETES";
        if (part === "uberneetess" || part === "uberneetes") return "KUBERNETES";
        return part.toUpperCase();
      })
      .join(" ")
    : "N/A";
};

// Additional helper functions you might need
export const formatNumber = (num) => {
  if (typeof num !== 'number') return "0";
  return num.toLocaleString();
};

export const formatDuration = (seconds) => {
  if (!seconds) return "0s";
  return `${seconds.toFixed(2)}s`;
};

export const getSeverityColor = (severity) => {
  const severityMap = {
    critical: COLORS.critical,
    high: COLORS.high,
    medium: COLORS.medium,
    low: COLORS.low,
    info: COLORS.info,
  };
  return severityMap[severity?.toLowerCase()] || COLORS.info;
};