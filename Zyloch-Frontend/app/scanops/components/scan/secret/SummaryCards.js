import React from "react";
import { FileText, AlertTriangle, ShieldCheck } from "lucide-react";

const SummaryCards = ({
  filesScanned,
  totalIssues,
  severityBreakdown = { critical: 0, high: 0, medium: 0, low: 0 },
}) => {
  const cards = [
    {
      label: "Files Scanned",
      value: filesScanned,
      icon: FileText,
      accent: "#3B82F6",
    },
    {
      label: "Total Issues",
      value: totalIssues,
      icon: AlertTriangle,
      accent: "var(--high)",
    },
    {
      label: "Medium Issues",
      value: severityBreakdown.medium,
      icon: AlertTriangle,
      accent: "var(--medium)",
    },
    {
      label: "Low Issues",
      value: severityBreakdown.low,
      icon: ShieldCheck,
      accent: "var(--color-primary)",
    },
  ];

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4 w-full">
      {cards.map((card) => (
        <SummaryCard
          key={card.label}
          label={card.label}
          value={card.value}
          icon={card.icon}
          accent={card.accent}
        />
      ))}
    </div>
  );
};

const SummaryCard = ({ label, value, icon: Icon, accent }) => (
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
      background: `color-mix(in srgb, ${accent} 4%, var(--surface))`,
      border: `1px solid color-mix(in srgb, ${accent} 15%, var(--border))`,
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
        background: `color-mix(in srgb, ${accent} 12%, var(--surface))`,
        border: `1px solid color-mix(in srgb, ${accent} 22%, var(--border))`,
        flexShrink: 0,
      }}
    >
      <Icon style={{ width: "18px", height: "18px", color: accent }} />
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
          color: accent,
        }}
      >
        {value}
      </strong>
    </div>
  </div>
);

export default SummaryCards;