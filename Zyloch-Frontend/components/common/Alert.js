// components/common/Alert.js
export default function Alert({
  children,
  variant = "info",
  className = "",
  ...props
}) {
  const variants = {
    info: "bg-info/10 text-info border-info/30",
    success: "bg-success/10 text-success border-success/30",
    warning: "bg-warning/10 text-warning border-warning/30",
    danger: "bg-danger/10 text-danger border-danger/30",
  };

  const baseClass = `
    p-4
    rounded-md
    border
    text-sm
    font-medium
    ${variants[variant]}
    ${className}
  `
    .trim()
    .replace(/\s+/g, " ");

  return (
    <div className={baseClass} role="alert" {...props}>
      {children}
    </div>
  );
}
