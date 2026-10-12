"use client";

import React from "react";
import dynamic from "next/dynamic";
import IssuesBySeverityCard from "../shared/IssuesBySeverityCard";
import SecurityScoreCard from "../shared/SecurityScoreCard";

const PieChart3D = dynamic(() => import("@/components/charts/PieChartUI"), {
  ssr: false,
});

const PATTERN_COLORS = [
  "#3B82F6", // Blue
  "#8B5CF6", // Purple
  "#EC4899", // Pink
  "#10B981", // Emerald
  "#F59E0B", // Amber
  "#06B6D4", // Cyan
  "#6366F1", // Indigo
  "#F97316", // Orange
];

const ChartsSection = ({ severityData, pieChartData = [], securityScore = 0 }) => {
  const formattedChartData = (pieChartData || []).map((item, idx) => ({
    name: item.name || "Unknown",
    value: Number(item.value) || 0,
    color: item.color && item.color.startsWith("#") ? item.color : PATTERN_COLORS[idx % PATTERN_COLORS.length],
  })).filter((item) => item.value > 0);

  const totalCount = formattedChartData.reduce((sum, item) => sum + item.value, 0);
  const hasData = formattedChartData.length > 0;

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-6 items-stretch">
      {/* Security Score Card */}
      <SecurityScoreCard score={securityScore} />

      {/* Issues by Severity Card */}
      <IssuesBySeverityCard
        severityData={severityData}
        title="Issues by Severity"
      />

      {/* Finding Types Distribution Card */}
      <div
        className="rounded-2xl border border-[var(--border)] bg-[var(--surface)] p-6 shadow-2 flex flex-col justify-between items-stretch hover:translate-y-[-2px] hover:shadow-xl transition-all duration-300"
        style={{ minHeight: "280px" }}
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
            Finding Types Distribution
          </h4>

          {hasData && (
            <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-semibold text-[var(--muted)] bg-[var(--elevated-surface)] border border-[var(--border)]">
              <span>Types:</span>
              <strong className="text-[var(--text)] font-bold">{formattedChartData.length}</strong>
            </span>
          )}
        </div>

        {hasData ? (
          <div className="flex flex-row items-center justify-between gap-6 w-full flex-grow overflow-hidden py-1">
            <div className="w-[160px] h-[160px] shrink-0 flex items-center justify-center">
              <PieChart3D
                data={formattedChartData}
                height={160}
                innerRadius={50}
                outerRadius={75}
                showLegend={false}
                showCenterText={false}
              />
            </div>

            {/* Legend Container */}
            <div className="flex flex-col gap-2 flex-grow min-w-0 max-h-[180px] overflow-y-auto pr-1">
              {formattedChartData.map((item, index) => {
                const color = item.color;
                const value = Number(item.value) || 0;
                const pct = totalCount > 0 ? Math.round((value / totalCount) * 100) : 0;

                return (
                  <div
                    key={`${item.name}-${index}`}
                    className="flex items-center justify-between w-full px-2 py-1 rounded-lg hover:bg-[var(--elevated-surface)]/60 transition-colors"
                  >
                    <div className="flex items-center gap-2.5 min-w-0">
                      <span
                        className="w-2.5 h-2.5 rounded-full shrink-0"
                        style={{
                          backgroundColor: color,
                          boxShadow: `0px 0px 8px ${color}80`,
                        }}
                      />
                      <span
                        className="font-semibold text-xs text-[var(--text)] whitespace-nowrap overflow-hidden text-ellipsis"
                        title={item.name}
                      >
                        {item.name}:
                      </span>
                    </div>

                    <div className="flex items-center gap-2 shrink-0 ml-3">
                      <span className="font-bold text-sm text-[var(--text)]">
                        {value}
                      </span>
                      {totalCount > 0 && value > 0 && (
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
            No finding type data available
          </div>
        )}
      </div>
    </div>
  );
};

export default ChartsSection;