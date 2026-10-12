"use client";

import {
  Zap,
  TrendingUp
} from "lucide-react";
import { useState } from "react";
import { formatScannerDisplayName } from "../utils";
import { normalizeScannerKey } from "../../shared/scannerIcons";
import EmptyState from "../common/EmptyState";
import PieChart3D from "@/components/charts/PieChartUI";
import { useTheme } from "@/context/ThemeContext";
import { OVERVIEW_DS } from "../designSystem";
import ScannerIconTile from "./ScannerIconTile";

import SecurityScoreCard from "../../shared/SecurityScoreCard";
import IssuesBySeverityCard from "../../shared/IssuesBySeverityCard";

const DESIGN_SYSTEM = OVERVIEW_DS;

const CARD_SURFACE_STYLE = {
  boxSizing: "border-box",
  display: "flex",
  flexDirection: "column",
  alignItems: "flex-start",
  padding: DESIGN_SYSTEM.spacing.md,
  width: "100%",
  background: "var(--surface)",
  border: "1px solid var(--border)",
  borderRadius: DESIGN_SYSTEM.radius.lg,
  minWidth: 0,
  boxShadow: "var(--shadow-2)",
  transition: "transform var(--transition-fast), box-shadow var(--transition-fast)",
};

const CARD_HEADING_STYLE = {
  fontFamily: DESIGN_SYSTEM.typography.family,
  fontWeight: 700,
  fontSize: DESIGN_SYSTEM.typography.eyebrow,
  lineHeight: "16px",
  letterSpacing: "0.08em",
  textTransform: "uppercase",
  color: "var(--muted)",
  margin: 0,
};

const PremiumCard = ({ children, title, subtitle, icon, headerAction, minHeight = "400px" }) => (
  <div
    style={{
      ...CARD_SURFACE_STYLE,
      isolation: "isolate",
      position: "relative",
      minHeight,
    }}
    className="hover:translate-y-[-2px] hover:shadow-xl"
  >
    <div style={{
      display: "flex",
      justifyContent: "space-between",
      alignItems: "center",
      width: "100%",
      marginBottom: DESIGN_SYSTEM.spacing.sm,
    }}>
      <div style={{ display: "flex", flexDirection: "column", gap: "2px" }}>
        <h4 style={CARD_HEADING_STYLE}>
          {title}
        </h4>
        {subtitle && (
          <span style={{
            fontFamily: DESIGN_SYSTEM.typography.family,
            fontSize: "12px",
            lineHeight: "18px",
            color: "var(--muted)",
            opacity: 0.9,
          }}>
            {subtitle}
          </span>
        )}
      </div>
      {headerAction ? (
        <div>{headerAction}</div>
      ) : icon ? (
        <div style={{ color: "var(--muted)", opacity: 0.4 }}>
          {icon}
        </div>
      ) : null}
    </div>

    <div style={{ flexGrow: 1, width: "100%", display: "flex", flexDirection: "column" }}>
      {children}
    </div>
  </div>
);

// Helper to extract active scanner keys that have >0 findings
const getActiveScannerKeysWithFindings = (scansFindings, issuesByScanner) => {
  const activeKeys = new Set();

  if (scansFindings && typeof scansFindings === "object") {
    Object.entries(scansFindings).forEach(([key, rawItems]) => {
      let items = [];
      if (Array.isArray(rawItems)) {
        items = rawItems;
      } else if (rawItems && typeof rawItems === "object") {
        const values = Object.values(rawItems);
        if (values.every((entry) => Array.isArray(entry))) {
          items = values.flat();
        } else {
          items = values.filter((entry) => typeof entry === "object" && entry !== null);
        }
      }

      if (items.length > 0) {
        const baseKey = String(key || "")
          .replace(/[-_]findings$/i, "")
          .trim()
          .toLowerCase()
          .replace(/[\s_-]+/g, "");
        activeKeys.add(baseKey);
      }
    });
  }

  if (issuesByScanner && typeof issuesByScanner === "object") {
    Object.entries(issuesByScanner).forEach(([key, count]) => {
      if (Number(count || 0) > 0) {
        const baseKey = String(key || "")
          .trim()
          .toLowerCase()
          .replace(/[\s_-]+/g, "");
        activeKeys.add(baseKey);
      }
    });
  }

  return activeKeys;
};

const ScannerScores = ({ scoreSummary, severitySummary = {}, issuesByScanner = {}, scansFindings = {} }) => {
  const { theme } = useTheme();
  const isDark = theme === "dark";
  const [performanceView, setPerformanceView] = useState("grid");

  // Return early if no score data
  if (!scoreSummary) {
    return <EmptyState message="No score data available" />;
  }

  // Normalize severity values to numbers
  const normalizedSeverity = {
    critical: Number(severitySummary?.critical || 0),
    high: Number(severitySummary?.high || 0),
    medium: Number(severitySummary?.medium || 0),
    low: Number(severitySummary?.low || 0),
  };

  // Calculate and clamp overall score between 0-100
  const overallScore = Math.max(
    0,
    Math.min(100, Math.round(scoreSummary.overall_score || 0))
  );

  // Get color based on score range
  const getScoreColor = (score) => {
    if (score >= 90) return "var(--success)";
    if (score >= 70) return "var(--warning)";
    if (score >= 50) return "var(--color-accent)";
    return "var(--danger)";
  };

  const SCANNER_COLORS = [
    "#3B82F6", // Blue
    "#8B5CF6", // Purple
    "#EC4899", // Pink
    "#10B981", // Emerald
    "#F59E0B", // Amber
    "#06B6D4", // Cyan
    "#6366F1", // Indigo
    "#F97316", // Orange
  ];

  // Map scanner names to hex colors for charts
  const getScannerColor = (scannerName, index = 0) => {
    const scannerLower = String(scannerName || "")
      .toLowerCase()
      .replace(/[\s_-]+/g, "");

    const colorMap = {
      docker: "#3B82F6",
      dockerfile: "#3B82F6",
      container: "#3B82F6",
      kubernetes: "#8B5CF6",
      uberneetess: "#8B5CF6",
      uberneetes: "#8B5CF6",
      k8s: "#8B5CF6",
      workflow: "#EC4899",
      githubactions: "#EC4899",
      secret: "#06B6D4",
      secretscanner: "#06B6D4",
      sbom: "#10B981",
      iac: "#F59E0B",
      specscanner: "#6366F1",
      cis: "#F97316",
      cisagent: "#F97316",
    };

    return colorMap[scannerLower] || SCANNER_COLORS[index % SCANNER_COLORS.length];
  };

  // Severity badge configuration with exact hex colors for solid chart fills
  const severityBadgeConfig = [
    { key: "critical", label: "Critical", color: "#EF4444" }, // Red
    { key: "high", label: "High", color: "#FB923C" },      // Neon Carrot
    { key: "medium", label: "Medium", color: "#FACC15" },    // Candlelight
    { key: "low", label: "Low", color: "#22D3EE" },       // Bright Turquoise
  ];

  // Prepare data for severity pie chart
  const severityChartData = severityBadgeConfig.map(({ key, label, color }) => ({
    name: label,
    value: normalizedSeverity[key],
    color,
  }));

  // Prepare data for issues by scanner chart (only scanners with >0 issues)
  const issuesByScannerChartData = Object.entries(issuesByScanner)
    .filter(([_, count]) => Number(count || 0) > 0)
    .map(([scanner, count], idx) => ({
      name: formatScannerDisplayName(scanner),
      value: Number(count || 0),
      color: getScannerColor(scanner, idx),
    }));

  const activeScannerKeys = getActiveScannerKeysWithFindings(scansFindings, issuesByScanner);

  // Filter scanner scores to only scanners that have findings/issues (or penalized score)
  const allSubscanScores = Object.entries(scoreSummary?.score_by_subscan || {});
  const filteredSubscanScores = activeScannerKeys.size > 0
    ? allSubscanScores.filter(([scanner, score]) => {
        const norm = String(scanner || "").trim().toLowerCase().replace(/[\s_-]+/g, "");
        for (const active of activeScannerKeys) {
          if (active === norm || active.includes(norm) || norm.includes(active)) {
            return true;
          }
        }
        if (Number(score || 0) < 100) {
          return true;
        }
        return false;
      })
    : allSubscanScores;

  // Prepare data for scanner scores chart
  const scannerScoreData = filteredSubscanScores.map(
    ([scanner, score]) => ({
      name: formatScannerDisplayName(scanner),
      value: Number(score || 0),
      color: getScannerColor(scanner),
    })
  );

  // Get performance status text based on percentage
  const getScannerPerformanceStatus = (percentage) => {
    const value = Number(percentage || 0);
    if (value >= 90) return "Excellent";
    if (value >= 80) return "Good";
    if (value >= 70) return "Moderate";
    return "Needs Improvement";
  };

  // Create scanner performance table rows
  const scannerPerformanceRows = scannerScoreData.map((item) => ({
    scanner: item.name,
    percentage: item.value,
    status: getScannerPerformanceStatus(item.value),
  }));

  // Check if data exists for conditional rendering
  const hasSeverityData = severityChartData.some((item) => item.value > 0);
  const hasScannerScoreData = scannerScoreData.some((item) => item.value > 0);

  const performanceTabs = (
    <div
      className="inline-flex items-center gap-1 rounded-2xl border p-1.5"
      style={{
        background: "color-mix(in srgb, var(--surface) 75%, var(--elevated-surface))",
        borderColor: "color-mix(in srgb, var(--border) 90%, transparent)",
        boxShadow: "inset 0 1px 0 color-mix(in srgb, var(--text) 6%, transparent)",
      }}
    >
      <button
        type="button"
        onClick={() => setPerformanceView("grid")}
        aria-pressed={performanceView === "grid"}
        className={`inline-flex h-10 w-10 items-center justify-center rounded-xl border transition-all duration-200 ${performanceView === "grid"
          ? "text-[var(--color-primary)]"
          : "text-muted hover:text-text"
          }`}
        title="Default view"
        aria-label="Default view"
        style={
          performanceView === "grid"
            ? {
              background: `color-mix(in srgb, ${DESIGN_SYSTEM.colors.primary} 16%, var(--surface))`,
              borderColor: `color-mix(in srgb, ${DESIGN_SYSTEM.colors.primary} 44%, var(--border))`,
              boxShadow: `0 6px 14px color-mix(in srgb, ${DESIGN_SYSTEM.colors.primary} 20%, transparent)`,
            }
            : {
              background: "transparent",
              borderColor: "transparent",
            }
        }
      >
        <Zap className="h-5 w-5" strokeWidth={2} />
      </button>
      <button
        type="button"
        onClick={() => setPerformanceView("chart")}
        aria-pressed={performanceView === "chart"}
        className={`inline-flex h-10 w-10 items-center justify-center rounded-xl border transition-all duration-200 ${performanceView === "chart"
          ? "text-[var(--color-primary)]"
          : "text-muted hover:text-text"
          }`}
        title="Chart view"
        aria-label="Chart view"
        style={
          performanceView === "chart"
            ? {
              background: `color-mix(in srgb, ${DESIGN_SYSTEM.colors.primary} 16%, var(--surface))`,
              borderColor: `color-mix(in srgb, ${DESIGN_SYSTEM.colors.primary} 44%, var(--border))`,
              boxShadow: `0 6px 14px color-mix(in srgb, ${DESIGN_SYSTEM.colors.primary} 20%, transparent)`,
            }
            : {
              background: "transparent",
              borderColor: "transparent",
            }
        }
      >
        <TrendingUp className="h-5 w-5" strokeWidth={2} />
      </button>
    </div>
  );

  return (
    <div className="w-full space-y-6">


      {/* Top row - Three metric cards */}
      <div className="w-full grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-6 items-stretch">

        {/* Card 1: Security Score matching all scanner pages */}
        <SecurityScoreCard score={overallScore} minHeight="300px" />

        {/* Card 2: Issues by Severity matching all scanner pages */}
        <IssuesBySeverityCard
          severityCounts={normalizedSeverity}
          title="Issues by Severity"
          minHeight="300px"
        />

        {/* Card 3: Issues by Scanner with Chart and Legend */}
        <div
          style={{
            ...CARD_SURFACE_STYLE,
            width: "100%",
            minHeight: "300px",
          }}
          className="hover:translate-y-[-2px] hover:shadow-xl"
        >
          <div className="flex items-center justify-between gap-2 mb-2 w-full">
            <h4 style={CARD_HEADING_STYLE}>
              Issues by Scanner
            </h4>
            {issuesByScannerChartData && issuesByScannerChartData.length > 0 && (
              <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-semibold text-[var(--muted)] bg-[var(--elevated-surface)] border border-[var(--border)]">
                <span>Scanners:</span>
                <strong className="text-[var(--text)] font-bold">{issuesByScannerChartData.length}</strong>
              </span>
            )}
          </div>
          {issuesByScannerChartData && issuesByScannerChartData.length > 0 ? (
            <div className="flex flex-row items-center justify-between gap-6 w-full flex-grow overflow-hidden py-1">
              <div className="w-[160px] h-[160px] shrink-0 flex items-center justify-center">
                <PieChart3D
                  data={issuesByScannerChartData}
                  height={160}
                  innerRadius={50}
                  outerRadius={75}
                  showLegend={false}
                  showCenterText={false}
                />
              </div>

              {/* Legend Container */}
              <div className="flex flex-col gap-2 flex-grow min-w-0 max-h-[180px] overflow-y-auto pr-1">
                {issuesByScannerChartData.map((item, idx) => (
                  <div
                    key={idx}
                    className="flex items-center justify-between w-full px-2 py-1 rounded-lg hover:bg-[var(--elevated-surface)]/60 transition-colors"
                  >
                    <div className="flex items-center gap-2.5 min-w-0">
                      <span
                        className="w-2.5 h-2.5 rounded-full shrink-0"
                        style={{
                          backgroundColor: item.color,
                          boxShadow: `0px 0px 8px ${item.color}80`,
                        }}
                      />
                      <span
                        className="font-semibold text-xs text-[var(--text)] whitespace-nowrap overflow-hidden text-ellipsis"
                        title={item.name}
                      >
                        {item.name}:
                      </span>
                    </div>
                    <span className="font-bold text-sm text-[var(--text)] shrink-0 ml-3">
                      {item.value}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <EmptyState message="No scanner issue data available" />
          )}
        </div>
      </div>

      {/* Unified Scanner Performance + Scores */}
      <div className="grid grid-cols-1 gap-6">
        <PremiumCard
          title="Scanner Performance"
          subtitle="Switch between default and chart view"
          headerAction={performanceTabs}
          minHeight="460px"
        >
          {performanceView === "grid" ? (
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3.5 mt-3">
              {scannerPerformanceRows.map((row, index) => {
                const isGood = Number(row.percentage || 0) >= 80;
                const statusColor = isGood ? "#10B981" : "#F97316";
                const scannerKey = normalizeScannerKey(row.scanner);

                return (
                  <div
                    key={index}
                    style={{
                      background: "var(--surface)",
                      border: "1px solid var(--border)",
                      borderRadius: "16px",
                      padding: "14px 18px",
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "space-between",
                      gap: "12px",
                      minHeight: "70px",
                    }}
                    className="transition-all duration-300 hover:translate-y-[-1px] hover:shadow-md"
                  >
                    <div className="flex items-center gap-3.5 min-w-0">
                      <div className="shrink-0 flex items-center justify-center">
                        <ScannerIconTile scannerKey={scannerKey} isDark={isDark} />
                      </div>

                      <div className="flex min-w-0 flex-col justify-center">
                        <span
                          style={{
                            fontFamily: DESIGN_SYSTEM.typography.family,
                            fontSize: "15px",
                            fontWeight: "700",
                            color: "var(--text)",
                            whiteSpace: "nowrap",
                            overflow: "hidden",
                            textOverflow: "ellipsis",
                          }}
                        >
                          {row.scanner}
                        </span>
                        <div className="flex items-center gap-1.5 mt-0.5">
                          <span
                            style={{
                              width: "6px",
                              height: "6px",
                              borderRadius: "50%",
                              background: statusColor,
                              flexShrink: 0,
                            }}
                          />
                          <span
                            style={{
                              fontFamily: DESIGN_SYSTEM.typography.family,
                              fontSize: "11px",
                              color: "var(--muted)",
                              fontWeight: "600",
                              textTransform: "uppercase",
                              letterSpacing: "0.5px",
                            }}
                          >
                            {row.status}
                          </span>
                        </div>
                      </div>
                    </div>

                    <div className="flex shrink-0 items-center justify-end pl-2">
                      <span
                        style={{
                          fontFamily: DESIGN_SYSTEM.typography.family,
                          fontSize: "16px",
                          fontWeight: "800",
                          color: statusColor,
                        }}
                      >
                        {row.percentage}%
                      </span>
                    </div>
                  </div>
                );
              })}
            </div>
          ) : (
            <div style={{
              flexGrow: 1,
              width: "100%",
              display: "flex",
              flexDirection: "column",
              gap: "20px",
              paddingTop: "8px"
            }}>
              {hasScannerScoreData ? (
                <>
                  {/* Top Summary Row (Avg Score, Scanners, Needs Attention) - Figma Node 660:4898 */}
                  <div
                    className="grid grid-cols-3 rounded-xl border py-4"
                    style={{
                      background: "color-mix(in srgb, var(--surface) 92%, var(--elevated-surface))",
                      borderColor: "color-mix(in srgb, var(--border) 75%, transparent)",
                    }}
                  >
                    {/* Avg Score */}
                    <div className="flex flex-col items-center justify-center text-center px-4 border-r border-[var(--border)]">
                      <span style={{
                        fontFamily: DESIGN_SYSTEM.typography.family,
                        fontSize: "11px",
                        fontWeight: "500",
                        color: "var(--muted)",
                        marginBottom: "2px",
                      }}>
                        Avg score
                      </span>
                      <span style={{
                        fontFamily: DESIGN_SYSTEM.typography.family,
                        fontSize: "22px",
                        fontWeight: "700",
                        color: "#76E17D",
                      }}>
                        {overallScore}%
                      </span>
                    </div>

                    {/* Scanners Count */}
                    <div className="flex flex-col items-center justify-center text-center px-4 border-r border-[var(--border)]">
                      <span style={{
                        fontFamily: DESIGN_SYSTEM.typography.family,
                        fontSize: "11px",
                        fontWeight: "500",
                        color: "var(--muted)",
                        marginBottom: "2px",
                      }}>
                        Scanners
                      </span>
                      <span style={{
                        fontFamily: DESIGN_SYSTEM.typography.family,
                        fontSize: "22px",
                        fontWeight: "700",
                        color: "var(--text)",
                      }}>
                        {scannerPerformanceRows.length}
                      </span>
                    </div>

                    {/* Needs Attention (< 80) */}
                    <div className="flex flex-col items-center justify-center text-center px-4">
                      <span style={{
                        fontFamily: DESIGN_SYSTEM.typography.family,
                        fontSize: "11px",
                        fontWeight: "500",
                        color: "var(--muted)",
                        marginBottom: "2px",
                      }}>
                        Needs attention
                      </span>
                      <span style={{
                        fontFamily: DESIGN_SYSTEM.typography.family,
                        fontSize: "22px",
                        fontWeight: "700",
                        color: "#FF6467",
                      }}>
                        {scannerPerformanceRows.filter((r) => Number(r.percentage || 0) < 80).length}
                      </span>
                    </div>
                  </div>

                  {/* Legend Row - Right-Aligned */}
                  <div className="flex items-center justify-end gap-5 px-1">
                    <div className="flex items-center gap-1.5">
                      <span className="w-2.5 h-2.5 rounded-sm" style={{ background: "#FF6467" }} />
                      <span style={{ fontFamily: DESIGN_SYSTEM.typography.family, fontSize: "12px", fontWeight: "500", color: "var(--muted)" }}>
                        Critical (&lt;80)
                      </span>
                    </div>
                    <div className="flex items-center gap-1.5">
                      <span className="w-2.5 h-2.5 rounded-sm" style={{ background: "#FACC15" }} />
                      <span style={{ fontFamily: DESIGN_SYSTEM.typography.family, fontSize: "12px", fontWeight: "500", color: "var(--muted)" }}>
                        Warning (80–89)
                      </span>
                    </div>
                    <div className="flex items-center gap-1.5">
                      <span className="w-2.5 h-2.5 rounded-sm" style={{ background: "#76E17D" }} />
                      <span style={{ fontFamily: DESIGN_SYSTEM.typography.family, fontSize: "12px", fontWeight: "500", color: "var(--muted)" }}>
                        Good (90+)
                      </span>
                    </div>
                  </div>

                  {/* Horizontal Progress Bars List */}
                  <div className="w-full flex flex-col gap-3 py-1">
                    {scannerPerformanceRows.map((row, index) => {
                      const score = Math.max(0, Math.min(100, Math.round(Number(row.percentage || 0))));
                      const barFillColor =
                        score >= 90
                          ? "#76E17D"
                          : score >= 80
                          ? "#FACC15"
                          : "#FF6467";

                      return (
                        <div
                          key={index}
                          className="flex items-center gap-4 w-full group py-0.5"
                        >
                          {/* Left Label */}
                          <div
                            className="w-28 sm:w-36 shrink-0 truncate text-xs font-medium text-[var(--text)] text-left"
                            title={row.scanner}
                          >
                            {row.scanner}
                          </div>

                          {/* Bar Track & Fill */}
                          <div
                            className="flex-1 h-4 rounded-full overflow-hidden relative"
                            style={{
                              background: isDark ? "rgba(36, 49, 67, 1)" : "rgba(232, 237, 242, 1)",
                              border: "1px solid color-mix(in srgb, var(--border) 60%, transparent)",
                            }}
                          >
                            <div
                              className="h-full rounded-full transition-all duration-700 ease-out"
                              style={{
                                width: `${score}%`,
                                background: barFillColor,
                                boxShadow: `0 0 8px color-mix(in srgb, ${barFillColor} 40%, transparent)`,
                              }}
                            />
                          </div>

                          {/* Right Score */}
                          <div className="w-9 shrink-0 text-right text-xs font-bold text-[var(--muted)]">
                            {score}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </>
              ) : (
                <EmptyState message="No scanner score data available" />
              )}
            </div>
          )}
        </PremiumCard>
      </div>
    </div>
  );
};

export default ScannerScores;
