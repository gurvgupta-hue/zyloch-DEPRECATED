export const getSeverityBadgeStyle = (severity) => ({
  background: `color-mix(in srgb, var(--${severity || "medium"}) 16%, var(--surface))`,
  color: `var(--${severity || "medium"})`,
});

export const getSeverityTextColor = () => "text-muted";
export const getTypeTextColor = () => "text-muted";
export const getProviderBadgeStyle = () => "bg-elevated text-muted";