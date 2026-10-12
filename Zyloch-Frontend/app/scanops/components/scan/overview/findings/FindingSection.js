"use client";

import React from "react";
import { useTheme } from "@/context/ThemeContext";
import { OVERVIEW_CARD_STYLE, OVERVIEW_DS } from "../designSystem";
import ScannerIconTile from "../scores/ScannerIconTile";

const FindingSection = ({
  title,
  scannerType,
  count,
  files,
  score,
  color = "#3b82f6",
  className = "",
}) => {
  const { theme } = useTheme();
  const isDark = theme === "dark";

  return (
    <div
      className={`
      transition-all duration-300
      group
      hover:translate-y-[-2px] hover:shadow-xl
      ${className}
    `}
      style={{
        ...OVERVIEW_CARD_STYLE,
        padding: OVERVIEW_DS.spacing.x2,
      }}
    >
      <div className="flex h-full flex-col gap-3">
        <div className="flex min-h-[52px] items-start gap-3 min-w-0 justify-between">
          <div className="min-w-0 flex-1 font-bold text-[var(--text)] pt-0.5">
            <span
              className="block whitespace-normal break-words font-bold leading-snug"
              style={{ fontFamily: OVERVIEW_DS.typography.family, fontSize: OVERVIEW_DS.typography.body }}
            >
              {title || "N/A"}
            </span>
          </div>

          <ScannerIconTile
            scannerKey={scannerType || title}
            isDark={isDark}
            className="mt-0.5 transition-all duration-300 group-hover:scale-105"
          />
        </div>

        <div className="h-px w-full" style={{ background: "var(--border)" }} />

        <div className="grid grid-cols-3 gap-2 pt-1">
          <div className="text-center border-r border-[var(--border)] pr-2">
            <div
              className="font-semibold"
              style={{
                color,
                fontFamily: OVERVIEW_DS.typography.family,
                fontSize: OVERVIEW_DS.typography.label,
              }}
            >
              {score !== null && score !== undefined ? `${Number(score).toFixed(1)}%` : "-"}
            </div>
            <div
              className="text-[var(--muted)] uppercase"
              style={{
                fontFamily: OVERVIEW_DS.typography.family,
                fontSize: OVERVIEW_DS.typography.micro,
                letterSpacing: "0.08em",
              }}
            >
              Score
            </div>
          </div>

          <div className="text-center border-r border-[var(--border)] pr-2">
            <div
              className="font-semibold text-[var(--text)]"
              style={{
                fontFamily: OVERVIEW_DS.typography.family,
                fontSize: OVERVIEW_DS.typography.label,
              }}
            >
              {count}
            </div>
            <div
              className="text-[var(--muted)] uppercase"
              style={{
                fontFamily: OVERVIEW_DS.typography.family,
                fontSize: OVERVIEW_DS.typography.micro,
                letterSpacing: "0.08em",
              }}
            >
              Issues
            </div>
          </div>

          <div className="text-center">
            <div
              className="font-semibold text-[var(--text)]"
              style={{
                fontFamily: OVERVIEW_DS.typography.family,
                fontSize: OVERVIEW_DS.typography.label,
              }}
            >
              {files}
            </div>
            <div
              className="text-[var(--muted)] uppercase"
              style={{
                fontFamily: OVERVIEW_DS.typography.family,
                fontSize: OVERVIEW_DS.typography.micro,
                letterSpacing: "0.08em",
              }}
            >
              Files
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default FindingSection;
