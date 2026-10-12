"use client";

import React from "react";
import SmartTruncate from "@/components/ui/SmartTruncate";

const CommitInfo = ({ label, value, icon }) => (
  <div className="flex flex-col gap-2">
    {/* Label + Icon */}
    <div className="flex items-center gap-2">
      <div
        className="
          p-1.5 
          rounded-md 
          transition-transform duration-300 
          hover:scale-105
        "
        style={{ 
          background: "color-mix(in srgb, var(--color-primary) 10%, transparent)" 
        }}
      >
        {React.cloneElement(icon, {
          className: `
            ${icon.props.className || ''}
            w-4 h-4
            fill-[var(--color-primary)]
            transition-all duration-300
          `.trim()
        })}
      </div>

      <span
        className="text-xs font-medium"
        style={{ color: "var(--muted)" }}
      >
        {label}
      </span>
    </div>

    {/* Value Card */}
    <div
      className="text-sm rounded-lg transition-all duration-300"
      style={{
        color: "var(--text)",
        background: "var(--surface)",
        padding: "12px",
      }}
    >
      <SmartTruncate
        text={value}
        type="auto"
        className="leading-tight"
        iconSize={12}
        threshold={40}
        showIcon={false}
        truncatePattern="end"
      />
    </div>
  </div>
);

export default CommitInfo;
