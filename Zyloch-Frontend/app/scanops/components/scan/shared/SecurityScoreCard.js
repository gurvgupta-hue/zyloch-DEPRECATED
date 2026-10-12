"use client";

import React from "react";

const getScoreColor = (score) => {
  if (score >= 90) return "#10B981"; // Emerald
  if (score >= 70) return "#F59E0B"; // Amber
  if (score >= 50) return "#8B5CF6"; // Purple
  return "#EF4444"; // Red
};

const getScoreRating = (score) => {
  if (score >= 90) return "Excellent";
  if (score >= 80) return "Good";
  if (score >= 50) return "Fair";
  return "Needs Work";
};

export default function SecurityScoreCard({
  score = 0,
  title = "Security Score",
  subtitle = null,
  minHeight = "280px",
  className = "",
  style = {},
}) {
  const safeScore = typeof score === "number" && !Number.isNaN(score) ? score : Number(score) || 0;
  const boundedScore = Math.max(0, Math.min(100, Math.round(safeScore)));
  const scoreColor = getScoreColor(boundedScore);
  const ratingText = getScoreRating(boundedScore);

  const radius = 66;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference * (1 - boundedScore / 100);
  const gradId = `scoreGrad-${Math.round(boundedScore)}`;

  return (
    <div
      className={`rounded-2xl border border-[var(--border)] bg-[var(--surface)] p-6 shadow-2 flex flex-col justify-between items-stretch hover:translate-y-[-2px] hover:shadow-xl transition-all duration-300 ${className}`}
      style={{
        minHeight,
        ...style,
      }}
    >
      <div className="flex items-center justify-between gap-2 mb-2">
        <div className="flex flex-col gap-0.5">
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
          {subtitle && (
            <span
              style={{
                fontFamily: "var(--font-ui)",
                fontSize: "12px",
                lineHeight: "16px",
                color: "var(--muted)",
                opacity: 0.85,
              }}
            >
              {subtitle}
            </span>
          )}
        </div>

        <span
          className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-semibold tracking-wide uppercase"
          style={{
            backgroundColor: `color-mix(in srgb, ${scoreColor} 12%, var(--surface))`,
            color: scoreColor,
            border: `1px solid color-mix(in srgb, ${scoreColor} 30%, transparent)`,
          }}
        >
          <span
            className="w-1.5 h-1.5 rounded-full animate-pulse"
            style={{ backgroundColor: scoreColor }}
          />
          {ratingText}
        </span>
      </div>

      {/* Circular Progress Container */}
      <div className="flex justify-center items-center self-stretch flex-grow relative py-2">
        <div className="relative w-[160px] h-[160px] shrink-0">
          <svg
            width="160"
            height="160"
            viewBox="0 0 160 160"
            style={{ transform: "rotate(-90deg)" }}
            aria-hidden="true"
          >
            <defs>
              <linearGradient id={gradId} x1="0%" y1="0%" x2="100%" y2="100%">
                <stop offset="0%" stopColor={scoreColor} stopOpacity="1" />
                <stop offset="100%" stopColor={`color-mix(in srgb, ${scoreColor} 70%, #3B82F6)`} stopOpacity="0.85" />
              </linearGradient>
            </defs>
            <circle
              cx="80"
              cy="80"
              r={radius}
              fill="none"
              stroke="var(--bg-secondary)"
              strokeWidth="11"
              opacity="0.6"
            />
            <circle
              cx="80"
              cy="80"
              r={radius}
              fill="none"
              stroke={`url(#${gradId})`}
              strokeWidth="11"
              strokeDasharray={`${circumference}`}
              strokeDashoffset={`${strokeDashoffset}`}
              strokeLinecap="round"
              style={{
                transition: "stroke-dashoffset 1s cubic-bezier(0.4, 0, 0.2, 1)",
                filter: `drop-shadow(0 0 6px ${scoreColor}50)`,
              }}
            />
          </svg>
          <div className="absolute inset-0 flex flex-col justify-center items-center pointer-events-none">
            <span
              style={{
                fontFamily: "var(--font-ui)",
                fontWeight: "800",
                fontSize: "36px",
                lineHeight: "40px",
                letterSpacing: "-0.02em",
                color: "var(--text)",
              }}
            >
              {boundedScore}
            </span>
            <span
              style={{
                fontFamily: "var(--font-ui)",
                fontWeight: "600",
                fontSize: "11px",
                textTransform: "uppercase",
                letterSpacing: "0.06em",
                color: "var(--muted)",
                marginTop: "1px",
              }}
            >
              out of 100
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}
