export const COLORS = {
  // Workflow and technology colors
  workflow: "var(--color-primary)",
  docker: "var(--color-secondary)",
  kubernetes: "var(--color-accent)",
  
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
  
  // Additional subscan types
  secret: "var(--color-accent)",
  code: "var(--color-primary)",
  dependency: "var(--color-secondary)",
  infrastructure: "var(--info)",
  container: "var(--color-secondary)",
  sbom: "var(--success)",
  sast: "var(--color-primary)",
  dast: "var(--color-secondary)",
  sca: "var(--color-accent)",
  iac: "var(--info)",
};

export const capitalize = (str) => {
  if (!str) return "";
  return str.charAt(0).toUpperCase() + str.slice(1);
};

export const getPolicyColor = (policyCode) => {
  const colors = [
    COLORS.primary,
    COLORS.secondary,
    COLORS.accent,
    COLORS.info,
    COLORS.success,
    COLORS.warning,
  ];
  const index = policyCode
    ? policyCode.split("").reduce((a, c) => a + c.charCodeAt(0), 0)
    : 0;
  return colors[index % colors.length];
};

export const getSeverityColor = (severity) => {
  const colors = {
    critical: COLORS.critical,
    high: COLORS.high,
    medium: COLORS.medium,
    low: COLORS.low,
  };
  return colors[severity] || COLORS.info;
};
