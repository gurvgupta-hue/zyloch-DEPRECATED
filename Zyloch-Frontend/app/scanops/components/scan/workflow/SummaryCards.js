import { FileText, AlertTriangle, AlertCircle, CheckCircle2 } from "lucide-react";

const SummaryCards = ({ workflowFindings, summary, workflowSummary }) => {
  return (
    <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
      <SummaryCard
        label="Files Scanned"
        value={workflowFindings.length}
        icon={FileText}
        color="var(--color-primary)"
      />
      <SummaryCard
        label="Total Issues"
        value={summary?.issues_summary?.total_issues_by_subscan?.workflow || 0}
        icon={AlertTriangle}
        color="var(--warning)"
      />
      <SummaryCard
        label="Medium Issues"
        value={workflowSummary.medium || 0}
        icon={AlertCircle}
        color="var(--info)"
      />
      <SummaryCard
        label="Low Issues"
        value={workflowSummary.low || 0}
        icon={CheckCircle2}
        color="var(--success)"
      />
    </div>
  );
};

const SummaryCard = ({ label, value, icon: Icon, color }) => (
  <div
    style={{
      boxSizing: "border-box",
      display: "flex",
      flexDirection: "row",
      alignItems: "center",
      padding: "16px",
      gap: "12px",
      width: "100%",
      minHeight: "90px",
      background: `color-mix(in srgb, ${color} 4%, var(--surface))`,
      border: `1px solid color-mix(in srgb, ${color} 15%, var(--border))`,
      borderRadius: "16px",
      boxShadow: "var(--shadow-2)",
      transition: "transform 0.15s ease, box-shadow 0.15s ease",
    }}
    className="hover:translate-y-[-2px] hover:shadow-xl"
  >
    <div
      style={{
        width: "40px",
        height: "40px",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        borderRadius: "10px",
        background: `color-mix(in srgb, ${color} 12%, var(--surface))`,
        border: `1px solid color-mix(in srgb, ${color} 22%, var(--border))`,
        flexShrink: 0,
      }}
    >
      <Icon style={{ width: "18px", height: "18px", color }} />
    </div>
    <div style={{ display: "flex", flexDirection: "column", gap: "2px", minWidth: 0 }}>
      <p
        style={{
          margin: 0,
          fontFamily: "var(--font-ui)",
          fontSize: "11px",
          fontWeight: 700,
          letterSpacing: "0.08em",
          textTransform: "uppercase",
          color: "var(--muted)",
        }}
      >
        {label}
      </p>
      <strong
        style={{
          fontFamily: "var(--font-ui)",
          fontSize: "26px",
          fontWeight: 800,
          lineHeight: 1,
          color,
        }}
      >
        {value}
      </strong>
    </div>
  </div>
);

export default SummaryCards;