// components/common/Card.js
export default function Card({
  children,
  padding = "md",
  shadow = "md",
  className = "",
  ...props
}) {
  const paddings = {
    none: "p-0",
    sm: "p-4",
    md: "p-6",
    lg: "p-8",
  };

  const shadows = {
    none: "",
    sm: "shadow-1",
    md: "shadow-2",
    lg: "shadow-3",
  };

  const baseClass = `
    bg-[var(--surface)]
    rounded-lg
    border border-[var(--border)]
    ${paddings[padding] ?? paddings.md}
    ${shadows[shadow] ?? shadows.md}
    ${className}
  `
    .trim()
    .replace(/\s+/g, " ");

  return (
    <div className={baseClass} {...props}>
      {children}
    </div>
  );
}
