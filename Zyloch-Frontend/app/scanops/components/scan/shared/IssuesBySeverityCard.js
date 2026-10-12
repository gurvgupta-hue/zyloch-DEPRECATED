"use client";

import React from "react";
import dynamic from "next/dynamic";

const PieChart3D = dynamic(() => import("@/components/charts/PieChartUI"), {
  ssr: false,
});

const SEVERITY_CONFIG = [
  { key: "critical", label: "Critical", color: "#EF4444" },
  { key: "high", label: "High", color: "#FB923C" },
  { key: "medium", label: "Medium", color: "#FACC15" },
  { key: "low", label: "Low", color: "#22D3EE" },
];

export default function IssuesBySeverityCard({
  severityCounts = {},
  severityData = null,
  title = "Issues by Severity",
  className = "",
  style = {},
}) {
  // Normalize counts from either severityCounts object or severityData array
  const normalizedCounts = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
  };

  if (severityData && Array.isArray(severityData)) {
    severityData.forEach((item) => {
      const name = String(item.name || "").toLowerCase();
      if (name.includes("crit")) normalizedCounts.critical = Number(item.value) || 0;
      else if (name.includes("high")) normalizedCounts.high = Number(item.value) || 0;
      else if (name.includes("med")) normalizedCounts.medium = Number(item.value) || 0;
      else if (name.includes("low")) normalizedCounts.low = Number(item.value) || 0;
    });
  } else if (severityCounts && typeof severityCounts === "object") {
    SEVERITY_CONFIG.forEach(({ key }) => {
      normalizedCounts[key] = Number(
        severityCounts[key] ??
        severityCounts[key.toLowerCase()] ??
        severityCounts[key.toUpperCase()] ??
        0
      );
    });
  }

  const chartData = SEVERITY_CONFIG.map(({ key, label, color }) => ({
    name: label,
    value: normalizedCounts[key],
    color,
  }));

  const totalIssues = Object.values(normalizedCounts).reduce((sum, v) => sum + v, 0);
  const hasData = totalIssues > 0;

  return (
    <div
      className={`rounded-2xl border border-[var(--border)] bg-[var(--surface)] p-6 shadow-2 flex flex-col justify-between items-stretch hover:translate-y-[-2px] hover:shadow-xl transition-all duration-300 ${className}`}
      style={{
        minHeight: "280px",
        ...style,
      }}
    >
      <div className="flex items-center justify-between gap-2 mb-2">
        <h4
          style={{
            fontFamily: "var(--font-ui)",
            fontWeight: 700,
            fontSize: "11px",
            lineHeight: "16px",
            letterSpacing: "0.08em",
            textTransform: "uppercase",
            color: "var(--muted)",
            margin: 0,
          }}
        >
          {title}
        </h4>

        {hasData && (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-semibold text-[var(--muted)] bg-[var(--elevated-surface)] border border-[var(--border)]">
            <span>Total:</span>
            <strong className="text-[var(--text)] font-bold">{totalIssues}</strong>
          </span>
        )}
      </div>

      {hasData ? (
        <div className="flex flex-row items-center justify-between gap-6 w-full flex-grow overflow-hidden py-1">
          <div className="w-[160px] h-[160px] shrink-0 flex items-center justify-center">
            <PieChart3D
              data={chartData}
              height={160}
              innerRadius={50}
              outerRadius={75}
              showLegend={false}
              showCenterText={false}
            />
          </div>

          {/* Legend Container */}
          <div className="flex flex-col gap-2 flex-grow min-w-0">
            {SEVERITY_CONFIG.map(({ label, color, key }) => {
              const count = normalizedCounts[key];
              const pct = totalIssues > 0 ? Math.round((count / totalIssues) * 100) : 0;

              return (
                <div
                  key={key}
                  className="flex items-center justify-between w-full px-2 py-1 rounded-lg hover:bg-[var(--elevated-surface)]/60 transition-colors"
                >
                  <div className="flex items-center gap-2.5 min-w-0">
                    <div
                      className="w-2.5 h-2.5 rounded-full shrink-0"
                      style={{
                        background: color,
                        boxShadow: `0px 0px 8px ${color}`,
                      }}
                    />
                    <span
                      className="font-semibold text-xs whitespace-nowrap overflow-hidden text-ellipsis"
                      style={{ color }}
                    >
                      {label}:
                    </span>
                  </div>

                  <div className="flex items-center gap-2 shrink-0 ml-3">
                    <span className="font-bold text-sm text-[var(--text)]">
                      {count}
                    </span>
                    {totalIssues > 0 && count > 0 && (
                      <span className="text-[11px] font-medium text-[var(--muted)] opacity-75">
                        ({pct}%)
                      </span>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      ) : (
        <div className="flex flex-col items-center justify-center flex-grow py-8 text-muted text-xs">
          No severity data available
        </div>
      )}
    </div>
  );
}
