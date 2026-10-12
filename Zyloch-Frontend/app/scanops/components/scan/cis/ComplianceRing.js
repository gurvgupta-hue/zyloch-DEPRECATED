"use client";

import React from "react";
import { CheckCircle2 } from "lucide-react";

const scoreColor = (score) => {
  if (score >= 80) return "var(--success)";
  if (score >= 50) return "var(--warning)";
  return "var(--danger)";
};

const ComplianceRing = ({ score = 0 }) => {
  const clamped = Math.max(0, Math.min(100, Number(score) || 0));
  const radius = 42;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (clamped / 100) * circumference;
  const color = scoreColor(clamped);

  return (
    <div className="flex items-center gap-4">
      <div className="flex flex-col">
        <span className="text-[28px] font-bold leading-none text-[var(--text)]">
          {clamped.toFixed(2)}
          <span className="text-sm font-medium text-[var(--muted)]"> /100</span>
        </span>
        <span className="mt-2 inline-flex w-fit items-center rounded-full bg-[var(--elevated-surface)] px-2.5 py-1 text-[11px] font-medium text-[var(--muted)]">
          {clamped >= 80 ? "Good standing" : clamped >= 50 ? "Room to improve" : "Needs attention"}
        </span>
      </div>
      <div className="relative flex h-24 w-24 shrink-0 items-center justify-center">
        <svg width="96" height="96" viewBox="0 0 96 96" className="-rotate-90">
          <circle cx="48" cy="48" r={radius} fill="none" stroke="var(--border)" strokeWidth="8" />
          <circle
            cx="48"
            cy="48"
            r={radius}
            fill="none"
            stroke={color}
            strokeWidth="8"
            strokeLinecap="round"
            strokeDasharray={circumference}
            strokeDashoffset={offset}
            style={{ transition: "stroke-dashoffset 0.6s ease" }}
          />
        </svg>
        <CheckCircle2 className="absolute h-6 w-6" style={{ color }} strokeWidth={2.2} />
      </div>
    </div>
  );
};

export default ComplianceRing;
