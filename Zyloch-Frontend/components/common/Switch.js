export default function Switch({
  checked,
  onChange,
  disabled = false,
  size = "md",
  variant = "primary",
  className = "",
  ...props
}) {
  const sizes = {
    sm: {
      track: "w-10 h-6",
      thumb: "w-4 h-4",
      translate: "translate-x-4",
    },
    md: {
      track: "w-12 h-7",
      thumb: "w-5 h-5",
      translate: "translate-x-5",
    },
    lg: {
      track: "w-14 h-8",
      thumb: "w-6 h-6",
      translate: "translate-x-6",
    },
  };

  const variants = {
    primary: "bg-primary",
    secondary: "bg-secondary",
    accent: "bg-accent",
    success: "bg-success",
    danger: "bg-danger",
    warning: "bg-warning",
  };

  const s = sizes[size] ?? sizes.md;
  const activeColor = variants[variant] ?? variants.primary;

  const handleChange = (e) => {
    if (!disabled) onChange?.(e.target.checked);
  };

  return (
    <label
      className={`inline-flex items-center ${
        disabled ? "cursor-not-allowed" : "cursor-pointer"
      } ${className}`}
      {...props}
    >
      <input
        type="checkbox"
        checked={checked}
        onChange={handleChange}
        disabled={disabled}
        className="sr-only"
      />

      <div
        className={`
          relative rounded-full
          ${checked ? activeColor : "bg-elevated"}
          ${disabled ? "opacity-50" : ""}
          ${s.track}
        `}
        style={{
          transition: "background-color var(--transition-fast)",
        }}
      >
        <span
          className={`
            absolute
            bg-surface
            rounded-full
            ${s.thumb}
            ${checked ? s.translate : "translate-x-1"}
          `}
          style={{
            top: "var(--space-1)",
            transition: "transform var(--transition-fast)",
            boxShadow: "var(--shadow-sm)",
          }}
        />
      </div>
    </label>
  );
}
