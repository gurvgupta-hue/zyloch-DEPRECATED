"use client";

import React from "react";

const ControlBreakdown = ({ controlData = [], total = 0 }) => {
  if (controlData.length === 0) {
    return (
      <div className="flex items-center justify-center py-10 text-sm text-[var(--muted)]">
        No control violations recorded.
      </div>
    );
  }

  const maxValue = Math.max(...controlData.map((item) => item.count), 1);
  const top = controlData[0];
  const topPct = total > 0 ? ((top.count / total) * 100).toFixed(1) : "0.0";

  return (
    <div className="flex flex-col gap-4">
      {controlData.map((item) => (
        <div key={item.control} className="flex items-center gap-3">
          <span className="w-20 shrink-0 text-xs font-semibold text-[var(--text)]">{item.control}</span>
          <div className="h-2.5 flex-1 rounded-full bg-[var(--elevated-surface)]">
            <div
              className="h-full rounded-full"
              style={{
                width: `${Math.max(4, (item.count / maxValue) * 100)}%`,
                background: "var(--success)",
              }}
            />
          </div>
          <span className="w-6 shrink-0 text-right text-xs font-semibold text-[var(--text)]">{item.count}</span>
        </div>
      ))}

      {top && (
        <p className="pt-1 text-xs text-[var(--muted)]">
          <span className="mr-1.5 inline-block h-1.5 w-1.5 rounded-full bg-[var(--success)] align-middle" />
          {top.control} accounts for {topPct}% of all findings
        </p>
      )}
    </div>
  );
};

export default ControlBreakdown;
