import SmartTruncate from "@/components/ui/SmartTruncate";

const MetadataItem = ({ icon: Icon, label, value }) => (
  <div
    className="flex flex-col p-3 rounded-lg hover:shadow-1 transition-all duration-300 relative"
    style={{
      background: "var(--elevated-surface)",
      border: "1px solid var(--border)",
      borderLeft: "3px solid var(--color-violet-65, #8B5CF6)",
    }}
  >
    <div className="flex items-center gap-2 mb-2">
      <div
        className="p-1.5 rounded-md transition-transform duration-300"
        style={{
          background: "color-mix(in srgb, var(--color-violet-65) 10%, transparent)",
        }}
      >
        <Icon className="w-4 h-4" style={{ color: "var(--color-violet-65)" }} />
      </div>
      <span className="text-xs font-medium" style={{ color: "var(--muted)" }}>
        {label}
      </span>
    </div>
    <div className="min-w-0">
      <SmartTruncate
        text={typeof value === "string" ? value : String(value)}
        threshold={25}
        showIcon={false}
        className="text-base font-semibold leading-tight"
        style={{ color: "var(--text)" }}
      />
    </div>
  </div>
);

export default MetadataItem;
