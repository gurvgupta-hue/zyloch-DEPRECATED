// components/dashboard/utils/styles.js
export const getSeverityBadgeStyle = (severity) => {
  const styles = {
    critical: "badge-red text-critical",
    high: "badge-orange text-high",
    medium: "badge-yellow text-medium",
    low: "badge-blue text-low",
  };
  return styles[severity] || "bg-elevated text-muted";
};

export const getTypeBadgeStyle = (type) => {
  const styles = {
    docker: "badge-cyan text-primary",
    kubernetes: "badge-blue text-low",
    terraform: "badge-purple text-secondary",
    bicep: "bg-sky-500/15 text-sky-400",
    arm: "bg-orange-500/15 text-orange-400",
  };
  return styles[type] || "bg-elevated text-muted";
};

export const getProviderBadgeStyle = (provider) => {
  const styles = {
    aws: "badge-orange text-warning",
    azure: "badge-blue text-info",
    gcp: "badge-green text-success",
  };
  return styles[provider] || "bg-elevated text-muted";
};

export const getSeverityTextColor = (severity) => {
  const styles = {
    critical: "text-critical",
    high: "text-high",
    medium: "text-medium",
    low: "text-low",
  };
  return styles[severity] || "text-muted";
};

export const getTypeTextColor = (type) => {
  const styles = {
    docker: "text-primary",
    kubernetes: "text-low",
    terraform: "text-secondary",
    bicep: "text-sky-400",
    arm: "text-orange-400",
  };
  return styles[type] || "text-muted";
};