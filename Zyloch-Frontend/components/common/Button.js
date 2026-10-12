// components/common/Button.js
export default function Button({
  children,
  variant = "primary",
  size = "md",
  loading = false,
  className = "",
  type = "button",
  disabled = false,
  fullWidth = false,
  ...props
}) {
  const variants = {
    primary: "bg-primary text-on-primary hover:opacity-90",
    secondary: "bg-secondary text-on-secondary hover:opacity-90",
    accent: "bg-accent text-on-accent hover:opacity-90",
    outline: "border border-border text-primary hover:bg-surface",
    ghost: "text-primary hover:bg-surface",
    danger: "bg-danger text-on-danger hover:opacity-90",
  };

  const sizes = {
    sm: "px-3 py-1.5 text-xs",
    md: "px-4 py-2 text-sm",
    lg: "px-5 py-2.5 text-base",
  };

  return (
    <button
      type={type}
      disabled={disabled || loading}
      className={`
        inline-flex items-center justify-center gap-2
        rounded-md font-medium
        transition-colors duration-200
        focus:outline-none focus:ring-2 focus:ring-primary/30
        disabled:opacity-40 disabled:cursor-not-allowed
        ${fullWidth ? "w-full" : ""}
        ${variants[variant]}
        ${sizes[size]}
        ${className}
      `}
      {...props}
    >
      {loading && (
        <svg className="animate-spin h-4 w-4" viewBox="0 0 24 24">
          <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
          <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
        </svg>
      )}
      {children}
    </button>
  );
}