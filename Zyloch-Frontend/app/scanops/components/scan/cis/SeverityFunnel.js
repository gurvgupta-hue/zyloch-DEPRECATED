"use client";

import React from "react";

const ORDER = ["critical", "high", "medium", "low"];
const LABELS = { critical: "Critical", high: "High", medium: "Medium", low: "Low" };

const SeverityFunnel = ({ severityData = [] }) => {
  const byName = severityData.reduce((acc, item) => {
    acc[String(item.name).toLowerCase()] = item;
    return acc;
  }, {});

  const tiers = ORDER
    .map((key) => byName[key])
    .filter((item) => item && item.value > 0);

  const total = tiers.reduce((sum, item) => sum + item.value, 0) || 1;
  const maxValue = Math.max(...tiers.map((item) => item.value), 1);

  if (tiers.length === 0) {
    return (
      <div className="flex items-center justify-center py-10 text-sm text-[var(--muted)]">
        No severity findings recorded.
      </div>
    );
  }

  return (
    <div className="flex items-center gap-6">
      <div className="flex flex-1 flex-col items-center gap-1">
        {tiers.map((item, index) => {
          const widthPct = 30 + (item.value / maxValue) * 70;
          return (
            <div
              key={item.name}
              className="flex h-16 items-center justify-center text-lg font-bold text-white"
              style={{
                width: `${widthPct}%`,
                background: item.color,
                clipPath:
                  index === tiers.length - 1
                    ? "polygon(15% 0%, 85% 0%, 50% 100%)"
                    : "polygon(0% 0%, 100% 0%, 90% 100%, 10% 100%)",
              }}
            >
              {item.value}
            </div>
          );
        })}
      </div>

      <div className="flex flex-1 flex-col gap-3">
        {tiers.map((item) => (
          <div key={item.name} className="flex items-center justify-between gap-2 text-sm">
            <span className="flex items-center gap-2 text-[var(--text)]">
              <span className="h-2.5 w-2.5 rounded-full" style={{ background: item.color }} />
              {LABELS[item.name] || item.name}
            </span>
            <span className="flex items-center gap-2">
              <strong className="text-[var(--text)]">{item.value}</strong>
              <span className="text-xs text-[var(--muted)] w-12 text-right">
                {((item.value / total) * 100).toFixed(1)}%
              </span>
            </span>
          </div>
        ))}
        {ORDER.filter((key) => !byName[key] || byName[key].value === 0).length === ORDER.length - tiers.length && (
          <p className="text-xs text-[var(--muted)]">
            {ORDER.filter((key) => !byName[key] || byName[key].value === 0)
              .map((key) => LABELS[key])
              .join(", ")}
            : no findings
          </p>
        )}
      </div>
    </div>
  );
};

export default SeverityFunnel;
