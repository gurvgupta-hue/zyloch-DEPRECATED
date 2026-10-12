// components/common/Badge.js
export default function Badge({
  children,
  variant = "default",
  size = "md",
  className = "",
  ...props
}) {
  const variants = {
    default: "bg-surface text-text border border-border",
    primary: "bg-primary text-on-primary",
    secondary: "bg-secondary text-on-secondary",
    accent: "bg-accent text-on-accent",
    success: "bg-success text-on-success",
    danger: "bg-danger text-on-danger",
  };

  const sizes = {
    sm: "px-2 py-0.5 text-xs",
    md: "px-2.5 py-1 text-sm",
    lg: "px-3 py-1.5 text-base",
  };

  const baseClass = `
    inline-flex items-center justify-center
    rounded-full
    font-medium
    leading-none
    whitespace-nowrap
    select-none
    ${variants[variant] || variants.default}
    ${sizes[size] || sizes.md}
    ${className}
  `
    .trim()
    .replace(/\s+/g, " ");

  return (
    <span className={baseClass} {...props}>
      {children}
    </span>
  );
}
