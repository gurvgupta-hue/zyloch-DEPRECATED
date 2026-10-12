"use client";

import React from "react";
import { BarChart3, PieChart as PieChartIcon } from "lucide-react";

const ChartSwitcher = ({ type, setType, disabled = false }) => (
  <div
    className="flex items-center gap-1 p-1 rounded-lg border transition-all duration-200"
    style={{
      background: "var(--elevated-surface)",
      borderColor: "var(--border)",
      opacity: disabled ? 0.7 : 1,
    }}
  >
    {[
      { type: "bar", icon: BarChart3, label: "Bar" },
      { type: "pie", icon: PieChartIcon, label: "Pie" },
    ].map(({ type: chartType, icon: Icon, label }) => (
      <button
        key={chartType}
        onClick={() => !disabled && setType(chartType)}
        disabled={disabled}
        className={`flex items-center gap-2 px-3 py-1.5 rounded-md text-sm font-medium transition-all duration-200 ${
          disabled 
            ? "cursor-not-allowed opacity-60" 
            : type === chartType
              ? ""
              : "hover:text-[var(--text)] hover:bg-[var(--elevated-surface)] active:scale-95"
        }`}
        style={{
          color: type === chartType ? "var(--color-primary)" : "var(--muted)",
          background: type === chartType ? "var(--surface)" : "transparent",
          boxShadow: type === chartType ? "var(--shadow-1)" : "none",
        }}
        aria-pressed={type === chartType}
        aria-label={`Switch to ${label} chart`}
        aria-disabled={disabled}
      >
        <Icon size={16} className={disabled ? "opacity-60" : ""} />
        <span className="hidden sm:inline">{label}</span>
      </button>
    ))}
  </div>
);

export default ChartSwitcher;