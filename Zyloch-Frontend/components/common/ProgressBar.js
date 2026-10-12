// components/common/ProgressBar.js
export default function ProgressBar({
  value = 0,
  max = 100,
  size = "md",
  showLabel = false,
  className = "",
  ...props
}) {
  const percentage = Math.min(100, Math.max(0, (value / max) * 100));
  const sizes = { sm: "h-1", md: "h-2", lg: "h-3" };

  return (
    <div className={className} {...props}>
      {showLabel && (
        <div
          className="flex justify-between mb-1"
          style={{
            fontSize: "var(--font-size-sm)",
            color: "var(--muted)",
          }}
        >
          <span>{Math.round(percentage)}%</span>
          <span>
            {value}/{max}
          </span>
        </div>
      )}

      <div
        className={`w-full bg-elevated rounded-full overflow-hidden ${sizes[size]}`}
      >
        <div
          className="h-full bg-primary rounded-full"
          style={{
            width: `${percentage}%`,
            transition: "width var(--transition-normal)",
          }}
        />
      </div>
    </div>
  );
}
