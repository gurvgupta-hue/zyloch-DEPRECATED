import { AlertCircle, AlertTriangle, ShieldAlert, ShieldCheck } from "lucide-react";

const SEVERITY_COLORS = {
  critical: "var(--critical)",
  high: "var(--high)",
  medium: "var(--medium)",
  low: "var(--low)",
};

export const normalizeSeverity = (severity) => {
  const tone = String(severity || "").trim().toLowerCase();
  if (tone === "critical" || tone === "high" || tone === "medium" || tone === "low") {
    return tone;
  }
  return "unknown";
};

export const getSeverityIcon = (severity) => {
  const tone = normalizeSeverity(severity);
  if (tone === "critical") return ShieldAlert;
  if (tone === "high") return AlertTriangle;
  if (tone === "medium") return AlertCircle;
  if (tone === "low") return ShieldCheck;
  return AlertTriangle;
};

export const getSeverityColorToken = (severity) => {
  const tone = normalizeSeverity(severity);
  return SEVERITY_COLORS[tone] || "var(--warning)";
};

export const SEVERITY_FIGMA_COLORS = {
  critical: {
    text: "#EF4444",
    bg: "rgba(239, 68, 68, 0.15)",
    border: "rgba(239, 68, 68, 0.3)",
    dot: "#EF4444",
  },
  high: {
    text: "#F97316",
    bg: "rgba(249, 115, 22, 0.15)",
    border: "rgba(249, 115, 22, 0.3)",
    dot: "#F97316",
  },
  medium: {
    text: "#3B82F6",
    bg: "rgba(59, 130, 246, 0.15)",
    border: "rgba(59, 130, 246, 0.3)",
    dot: "#3B82F6",
  },
  low: {
    text: "#8B5CF6",
    bg: "rgba(139, 92, 246, 0.15)",
    border: "rgba(139, 92, 246, 0.3)",
    dot: "#8B5CF6",
  },
};

export const getFigmaSeverityBadgeStyle = (severity) => {
  const tone = normalizeSeverity(severity);
  const cfg = SEVERITY_FIGMA_COLORS[tone] || {
    text: "var(--text-secondary)",
    bg: "var(--elevated)",
    border: "var(--border)",
    dot: "var(--muted)",
  };

  return {
    backgroundColor: cfg.bg,
    color: cfg.text,
    borderColor: cfg.border,
  };
};

export const getSeverityBadgeStyle = (severity, { blur = false, variant = "default" } = {}) => {
  if (variant === "figma") {
    return getFigmaSeverityBadgeStyle(severity);
  }
  const color = getSeverityColorToken(severity);

  return {
    background: `color-mix(in srgb, ${color} 30%, var(--surface))`,
    border: `1px solid color-mix(in srgb, ${color} 62%, var(--border))`,
    color,
    ...(blur
      ? {
        backdropFilter: "blur(10px)",
        WebkitBackdropFilter: "blur(10px)",
      }
      : {}),
  };
};

export const formatSeverityLabel = (severity) => {
  const tone = normalizeSeverity(severity);
  if (tone === "unknown") return "Unknown";
  return tone.charAt(0).toUpperCase() + tone.slice(1);
};

export const TableSeverityBadge = ({ severity, className = "" }) => {
  const tone = normalizeSeverity(severity);
  const cfg = SEVERITY_FIGMA_COLORS[tone] || {
    text: "var(--text-secondary)",
    bg: "var(--elevated)",
    border: "var(--border)",
  };

  return (
    <span
      className={`inline-flex min-w-[68px] items-center justify-center rounded-[6px] px-2.5 py-1 text-xs font-semibold capitalize tracking-normal ${className}`}
      style={{
        backgroundColor: cfg.bg,
        color: cfg.text,
        border: `1px solid ${cfg.border}`,
      }}
    >
      {formatSeverityLabel(severity)}
    </span>
  );
};