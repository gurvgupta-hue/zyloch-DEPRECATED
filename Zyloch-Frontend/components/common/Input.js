// components/common/Input.js
export default function Input({
  label,
  error,
  helperText,
  className = "",
  ...props
}) {
  const baseClass = `
    w-full
    px-4 py-2.5
    bg-[var(--surface)]
    border rounded-md
    text-[var(--text)]
    transition-colors duration-200
    focus:outline-none
    focus:ring-2 focus:ring-[var(--primary)]/30
    focus:border-[var(--primary)]
    ${error ? "border-[var(--danger)]" : "border-[var(--border)]"}
    ${className}
  `
    .trim()
    .replace(/\s+/g, " ");

  return (
    <div className="w-full">
      {label && (
        <label className="block text-sm font-medium text-[var(--muted)] mb-1">
          {label}
        </label>
      )}

      <input className={baseClass} {...props} />

      {(error || helperText) && (
        <p
          className={`text-sm mt-1 ${
            error
              ? "text-[var(--danger)]"
              : "text-[var(--muted)]"
          }`}
        >
          {error || helperText}
        </p>
      )}
    </div>
  );
}
