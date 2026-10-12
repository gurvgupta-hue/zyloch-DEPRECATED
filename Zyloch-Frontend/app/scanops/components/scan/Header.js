"use client";

import React, { useState } from "react";
import { PlusCircle, RefreshCcw, Calendar } from "lucide-react";
import { formatApiText } from "./shared/textUtils";
import ScannerIconTile from "./overview/scores/ScannerIconTile";

export const BULK_OVERVIEW_DISABLED_HINT =
  "Full scans from Overview run only on the main or master branch. On other branches, start each scan from its dedicated ScanOps page.";

const ScanHeader = ({
  scanTitle,
  scanStatus,
  onStartNewScan,
  onRefresh,
  refreshing,
  tabs = null,
  activeTabId = null,
  onTabChange = null,
  newScanDisabled = false,
}) => {
  const [hoveredButton, setHoveredButton] = useState(null);
  const newScanTooltip = newScanDisabled ? BULK_OVERVIEW_DISABLED_HINT : "New Scan";

  const formatTitle = (title) => {
    if (!title) return "OVERVIEW";
    const normalized = String(title).replace(/[\s_-]+/g, "").toLowerCase();
    if (normalized === "overview") return "OVERVIEW";
    if (normalized === "iac" || normalized === "infrastructureascode") return "INFRASTRUCTURE AS CODE";
    if (normalized === "workflow" || normalized === "githubactionsworkflow") return "GITHUB ACTIONS WORKFLOW";
    if (normalized === "specscanner" || normalized === "apidiscovery") return "API DISCOVERY";
    if (normalized === "secretscanner" || normalized === "secret") return "SECRET SCANNER";
    if (normalized === "sbom") return "SBOM";
    if (normalized === "cis" || normalized === "cisagent") return "CIS AGENT";
    if (normalized === "skillscanner" || normalized === "aisecurityscanner") return "AI SECURITY SCANNER";
    return formatApiText(title);
  };

  const renderStatus = () => {
    if (!scanStatus) return null;

    if (typeof scanStatus === "string") {
      return (
        <span className="text-xs text-[var(--muted)] font-medium truncate">
          {scanStatus}
        </span>
      );
    }

    return <div className="min-w-0 truncate">{scanStatus}</div>;
  };

  return (
    <div className="w-full flex flex-col justify-center">
      <div className="flex items-center justify-between gap-2.5 sm:gap-4 w-full min-w-0">
        {/* ── Left: Title + Status + Optional Tabs ── */}
        <div className="flex items-center gap-2.5 sm:gap-3.5 min-w-0 flex-1 overflow-hidden">
          <div className="shrink-0 flex items-center justify-center">
            <ScannerIconTile scannerKey={scanTitle} size={18} tileSize={36} />
          </div>

          <div className="flex flex-col gap-0.5 min-w-0 flex-1 overflow-hidden">
            <div className="flex items-center gap-2 min-w-0">
              <h1 className="text-sm sm:text-base font-semibold text-[var(--text)] truncate">
                {formatTitle(scanTitle)}
              </h1>

              {/* Optional sub-tabs if present */}
              {tabs && tabs.length > 0 && (
                <div className="hidden sm:inline-flex items-center gap-1 p-0.5 rounded-lg bg-[var(--elevated-surface)] border border-[var(--border)] ml-1 shrink-0">
                  {tabs.map((tab) => {
                    const isActive = activeTabId === tab.id;
                    const Icon = tab.icon;
                    return (
                      <button
                        key={tab.id}
                        type="button"
                        onClick={() => onTabChange && onTabChange(tab.id)}
                        className={`inline-flex items-center gap-1.5 px-2.5 py-1 text-xs font-medium rounded-md transition-all ${isActive
                          ? "bg-[var(--surface)] text-[var(--color-primary)] shadow-sm border border-[var(--border)]"
                          : "text-[var(--muted)] hover:text-[var(--text)]"
                          }`}
                      >
                        {Icon && <Icon size={13} />}
                        <span>{tab.label}</span>
                      </button>
                    );
                  })}
                </div>
              )}
            </div>

            {scanStatus && (
              <div className="flex min-w-0 items-center gap-1.5 text-xs truncate">
                {typeof scanStatus === "string" && (
                  <Calendar size={12} className="text-[var(--muted)] flex-shrink-0" />
                )}
                {renderStatus()}
              </div>
            )}
          </div>
        </div>

        {/* ── Right: Action Buttons (Always visible and responsive) ── */}
        <div className="flex items-center gap-1.5 sm:gap-2 shrink-0 z-10">
          {/* Refresh */}
          <Tooltip label={refreshing ? "Refreshing..." : "Refresh"} visible={hoveredButton === "refresh"}>
            <button
              onMouseEnter={() => setHoveredButton("refresh")}
              onMouseLeave={() => setHoveredButton(null)}
              onClick={onRefresh}
              disabled={refreshing}
              aria-label="Refresh scan"
              className="flex items-center justify-center w-8 h-8 sm:w-9 sm:h-9 rounded-lg
                bg-[var(--elevated-surface)] border border-[var(--border)]
                text-[var(--color-secondary)] hover:bg-[var(--surface)]
                hover:border-[var(--color-secondary)]/40
                active:scale-95 disabled:opacity-50 disabled:cursor-not-allowed
                transition-all duration-150 shrink-0"
            >
              <RefreshCcw size={15} className={refreshing ? "animate-spin" : ""} />
            </button>
          </Tooltip>

          {/* New Scan */}
          <Tooltip
            label={newScanTooltip}
            visible={hoveredButton === "new"}
            multiline={newScanDisabled}
          >
            <span
              className="inline-flex shrink-0"
              onMouseEnter={() => setHoveredButton("new")}
              onMouseLeave={() => setHoveredButton(null)}
            >
              <button
                type="button"
                onClick={newScanDisabled ? undefined : onStartNewScan}
                disabled={newScanDisabled}
                aria-label={newScanDisabled ? "New scan unavailable on this branch" : "Start new scan"}
                className="flex items-center justify-center w-8 h-8 sm:w-9 sm:h-9 rounded-lg
                  bg-[var(--elevated-surface)] border border-[var(--border)]
                  text-[var(--color-accent)] hover:bg-[var(--surface)]
                  hover:border-[var(--color-accent)]/40
                  active:scale-95 disabled:opacity-50 disabled:cursor-not-allowed
                  disabled:hover:border-[var(--border)] disabled:hover:bg-[var(--elevated-surface)]
                  transition-all duration-150 shrink-0"
              >
                <PlusCircle size={15} />
              </button>
            </span>
          </Tooltip>
        </div>
      </div>

      {/* Mobile Tab Switcher for tabbed AI routes */}
      {tabs && tabs.length > 0 && (
        <div className="flex sm:hidden items-center gap-1 p-1 mt-2.5 rounded-lg bg-[var(--elevated-surface)] border border-[var(--border)] w-full">
          {tabs.map((tab) => {
            const isActive = activeTabId === tab.id;
            const Icon = tab.icon;
            return (
              <button
                key={tab.id}
                type="button"
                onClick={() => onTabChange && onTabChange(tab.id)}
                className={`flex-1 inline-flex items-center justify-center gap-1.5 py-1 px-2 text-xs font-medium rounded-md transition-all ${isActive
                  ? "bg-[var(--surface)] text-[var(--color-primary)] shadow-sm border border-[var(--border)]"
                  : "text-[var(--muted)] hover:text-[var(--text)]"
                  }`}
              >
                {Icon && <Icon size={12} />}
                <span className="truncate">{tab.label}</span>
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
};

/* ── Reusable tooltip wrapper ── */
const Tooltip = ({ label, visible, children, multiline = false }) => (
  <div className="relative shrink-0">
    {children}
    {visible && label && (
      <div
        className={`absolute top-full right-0 sm:right-auto sm:left-1/2 sm:-translate-x-1/2 mt-2 z-50
          rounded-md px-2.5 py-1.5 shadow-lg
          bg-[var(--surface)] border border-[var(--border)]
          text-[var(--text)] text-xs font-medium
          animate-fadeIn pointer-events-none
          ${multiline ? "max-w-[min(18rem,calc(100vw-2rem))] whitespace-normal text-left leading-snug" : "whitespace-nowrap"}`}
      >
        {label}
        <span
          className="absolute -top-[5px] right-3 sm:right-auto sm:left-1/2 sm:-translate-x-1/2
            w-2 h-2 rotate-45
            bg-[var(--surface)] border-l border-t border-[var(--border)]"
        />
      </div>
    )}
  </div>
);

export default ScanHeader;