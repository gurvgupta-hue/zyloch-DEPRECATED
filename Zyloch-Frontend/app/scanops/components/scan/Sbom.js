"use client";

import React, { useRef, useState, useMemo, useEffect } from "react";
import {
  Package,
  Layers,
  ShieldAlert,
  Settings,
  Calendar,
  User,
  GitCompare,
  GitCommitHorizontal,
  Search,
  ChevronLeft,
  ChevronRight,
  ChevronDown,
  ChevronUp,
  AlertTriangle,
  CheckCircle,
  Clock,
  HelpCircle,
  ExternalLink,
  Tag,
  ShieldCheck,
  FileText,
  Info,
  Check,
} from "lucide-react";
import { Tooltip } from "@mui/material";
import LICENSE_POLICY_MAP from "@/data/LICENSE_POLICY_MAP.json";
import ScannerIconTile from "./overview/scores/ScannerIconTile";
import BarChartUI from "@/components/charts/BarChartUI";
import PieChartUI from "@/components/charts/PieChartUI";
import RadarChartUI from "@/components/charts/RadarChartUI";
import RadialBarChartUI from "@/components/charts/RadialBarChartUI";
import SmartTruncate from "@/components/ui/SmartTruncate";
import { useScanStore } from "@/store/useScanStore";
import LoadingState from "./workflow/LoadingState";
import ErrorState from "./workflow/ErrorState";
import EmptyState from "./sbom/EmptyState";
import styles from "./workflow/Workflow.module.css";
import {
  formatSeverityLabel,
  getSeverityBadgeStyle,
  getSeverityIcon,
} from "./shared/severityVisuals";
import TablePagination from "./shared/TablePagination";
import { useInteractiveTable } from "./shared/useInteractiveTable";
import SecurityScoreCard from "./shared/SecurityScoreCard";
import ScanMetadataOverview from "./shared/ScanMetadataOverview";

// --- Configuration & Constants ---
const CONFIG = {
  LAYOUT: {
    TABLE_ITEMS_PER_PAGE: 50,
    GRID_ITEMS_PER_PAGE: 12,
    CHART_BAR_SIZE: 32,
    STAT_CARD_HEIGHT: "auto",
    SPACING: {
      PAGE_GAP: "var(--space-6)",
      SECTION_GAP: "var(--space-6)",
      CARD_GAP: "var(--space-4)",
      ELEMENT_GAP: "var(--space-4)",
      PADDING: "var(--space-5)",
    },
    BORDERS: {
      RADIUS: "var(--radius-lg)",
      WIDTH: "1px",
    }
  },
  THEME: {
    FONTS: {
      PRIMARY: "Inter, sans-serif",
      MONO: "var(--font-mono)",
    },
    GRADIENTS: {
      HEADER: "linear-gradient(90deg, color-mix(in srgb, var(--color-primary) 10%, transparent) 0%, color-mix(in srgb, var(--info) 5%, transparent) 50%, transparent 100%)",
      PAGE_BG: "var(--bg)",
    },
  },
  COLORS: {
    PURPLE: { base: "var(--color-primary)", light: "var(--color-primary)", bg: "color-mix(in srgb, var(--color-primary) 10%, transparent)", border: "var(--color-primary)", iconBg: "color-mix(in srgb, var(--color-primary) 20%, transparent)" },
    VIVIOLET: { base: "var(--color-secondary)", light: "var(--color-secondary)", bg: "color-mix(in srgb, var(--color-secondary) 10%, transparent)", border: "var(--color-secondary)" },
    CYAN: { base: "var(--info)", light: "var(--info)", bg: "color-mix(in srgb, var(--info) 10%, transparent)", border: "var(--info)" },
    INDIGO: { base: "var(--color-accent)", light: "var(--color-accent)", bg: "color-mix(in srgb, var(--color-accent) 10%, transparent)", border: "var(--color-accent)" },
    GRAY: { base: "var(--muted)", dark: "var(--muted)", border: "var(--border)", bg: "var(--surface)", surface: "var(--surface)" },
    SUCCESS: "var(--success)",
    WARNING: "var(--warning)",
    DANGER: "var(--danger)",
  }
};

// --- StatCard Component ---
const StatCard = ({ label, value, status, icon: Icon, color }) => (
  <div
    className="flex flex-col items-start p-6 gap-3 w-full bg-[var(--surface)] border border-[var(--border)] shadow-[var(--shadow-soft)] transition-all duration-300 hover:shadow-[var(--shadow-md)] group"
    style={{
      borderRadius: "var(--radius-lg)",
      height: CONFIG.LAYOUT.STAT_CARD_HEIGHT,
      borderLeft: `4px solid ${color}`
    }}
  >
    <div className="flex justify-between items-start w-full">
      <div
        className="flex items-center justify-center p-2 rounded-lg transition-colors duration-300"
        style={{ background: `color-mix(in srgb, ${color} 10%, transparent)` }}
      >
        <Icon size={20} style={{ color }} className="group-hover:scale-110 transition-transform duration-300" />
      </div>
      {status && (
        <span className="text-[10px] font-bold px-2 py-0.5 rounded-full uppercase tracking-wider"
          style={{ background: `color-mix(in srgb, ${color} 10%, transparent)`, color }}>
          {status}
        </span>
      )}
    </div>
    <div className="flex flex-col gap-1">
      <span className="text-2xl font-bold tracking-tight text-[var(--text)] font-sans">{value}</span>
      <span className="text-xs font-semibold uppercase tracking-widest text-[var(--muted)] font-sans">{label}</span>
    </div>
  </div>
);

// --- CustomHeaderIcon Component ---
const CustomHeaderIcon = () => (
  <svg width="24" height="24" viewBox="35 35 25 25" fill="none" xmlns="http://www.w3.org/2000/svg">
    <path d="M47.9369 49.5C47.8477 49.1539 47.6673 48.8381 47.4146 48.5854C47.1618 48.3327 46.846 48.1523 46.4999 48.063L40.3649 46.481C40.2603 46.4513 40.1681 46.3883 40.1026 46.3014C40.037 46.2146 40.0015 46.1088 40.0015 46C40.0015 45.8912 40.037 45.7854 40.1026 45.6986C40.1681 45.6118 40.2603 45.5487 40.3649 45.519L46.4999 43.936C46.8459 43.8468 47.1616 43.6666 47.4143 43.414C47.6671 43.1615 47.8475 42.8459 47.9369 42.5L49.5189 36.365C49.5483 36.2599 49.6113 36.1673 49.6983 36.1014C49.7852 36.0355 49.8913 35.9998 50.0004 35.9998C50.1096 35.9998 50.2157 36.0355 50.3026 36.1014C50.3896 36.1673 50.4525 36.2599 50.4819 36.365L52.0629 42.5C52.1522 42.8461 52.3326 43.1619 52.5853 43.4146C52.838 43.6673 53.1539 43.8477 53.4999 43.937L59.6349 45.518C59.7404 45.5471 59.8335 45.61 59.8998 45.6971C59.9661 45.7841 60.002 45.8906 60.002 46C60.002 46.1094 59.9661 46.2159 59.8998 46.3029C59.8335 46.39 59.7404 46.4529 59.6349 46.482L53.4999 48.063C53.1539 48.1523 52.838 48.3327 52.5853 48.5854C52.3326 48.8381 52.1522 49.1539 52.0629 49.5L50.4809 55.635C50.4515 55.7401 50.3886 55.8327 50.3016 55.8986C50.2147 55.9646 50.1086 56.0003 49.9994 56.0003C49.8903 56.0003 49.7842 55.9646 49.6973 55.8986C49.6103 55.8327 49.5473 55.7401 49.5179 55.635L47.9369 49.5Z" stroke="#19444f" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
    <path d="M58 37V41" stroke="#19444f" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
    <path d="M60 39H56" stroke="#19444f" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
    <path d="M42 51V53" stroke="#19444f" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
    <path d="M43 52H41" stroke="#19444f" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
  </svg>
);

// --- SectionHeader Component ---
const SectionHeader = React.memo(({ title, subtitle }) => (
  <div
    className="flex flex-col items-start w-full rounded-[16px] border border-[var(--border)] overflow-hidden"
    style={{
      padding: "24px",
      gap: "8px",
      background: CONFIG.THEME.GRADIENTS.HEADER,
      alignSelf: "stretch",
      height: "120px"
    }}
  >
    <div className="flex flex-row items-center p-0 gap-[12px] h-[44px]">
      <ScannerIconTile scannerKey="sbom" size={22} tileSize={44} />
      <div className="flex flex-col items-start p-0">
        <h1
          className="whitespace-nowrap font-bold text-[22.7px] leading-[32px] font-sans text-[var(--text)] flex items-center"
        >
          {title}
        </h1>
      </div>
    </div>
    <div className="flex flex-col items-start p-0 w-full h-[20px]">
      <p className="font-normal text-[13.6px] leading-[20px] font-sans text-[var(--muted)] flex items-center">
        {subtitle}
      </p>
    </div>
  </div>
));

// --- MetricBar Component ---
const MetricBar = React.memo(({ label, percentage, color }) => (
  <div className="flex flex-col gap-2 w-full">
    <div className="flex flex-row justify-between items-center w-full">
      <span className="font-normal text-sm text-gray-400 font-sans truncate pr-2">{label}</span>
      <span className="font-semibold text-sm text-white font-sans">{percentage}%</span>
    </div>
    <div className="w-full h-2 rounded-full" style={{ background: CONFIG.COLORS.GRAY.border }}>
      <div
        className="h-full rounded-full transition-all duration-500"
        style={{ width: `${percentage}%`, background: color }}
      ></div>
    </div>
  </div>
));

// --- ContentBlock Component ---
const ContentBlock = React.memo(({ title, description, children, className = "" }) => (
  <div
    className={`flex flex-col w-full border border-[var(--border)] bg-[var(--surface)] shadow-[var(--shadow-soft)] transition-all duration-300 ${className}`}
    style={{
      borderRadius: "var(--radius-lg)",
    }}
  >
    <div className="px-[var(--space-6)] py-[var(--space-4)]">
      {title && (
        <div className="text-[var(--text)] text-lg font-semibold leading-snug">
          {title}
        </div>
      )}
      {description && (
        <div className="mt-1 text-[var(--muted)] text-xs leading-snug">
          {description}
        </div>
      )}
    </div>
    <div className="px-[var(--space-6)] pb-[var(--space-6)] pt-0 flex-1 overflow-visible">
      {children}
    </div>
  </div>
));



// --- SbomRiskCharts Component ---
const SbomRiskCharts = React.memo(({ licenseTypes, packageManagers, score = 0 }) => (
  <section className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-6 items-stretch">
    <SecurityScoreCard score={score} />

    <article className={styles.panelCard}>
      <h3 style={{ margin: "0 0 4px", fontFamily: "var(--font-ui)", fontSize: "11px", fontWeight: 700, letterSpacing: "0.08em", textTransform: "uppercase", color: "var(--muted)" }}>License Distribution</h3>
      <p className="mb-3 text-xs text-[var(--muted)]">Distribution of dependency licenses by category</p>
      {licenseTypes.length > 0 ? (
        <PieChartUI data={licenseTypes} hideLegend={false} height={200} />
      ) : (
        <div className={styles.chartLoading}>No license data</div>
      )}
    </article>

    <article className={styles.panelCard}>
      <h3 style={{ margin: "0 0 4px", fontFamily: "var(--font-ui)", fontSize: "11px", fontWeight: 700, letterSpacing: "0.08em", textTransform: "uppercase", color: "var(--muted)" }}>Package Managers</h3>
      <p className="mb-3 text-xs text-[var(--muted)]">Dependency counts by package manager and ecosystem</p>
      {packageManagers.length > 0 ? (
        <BarChartUI data={packageManagers} showLegend={false} barSize={CONFIG.LAYOUT.CHART_BAR_SIZE} height={200} />
      ) : (
        <div className={styles.chartLoading}>No package manager data</div>
      )}
    </article>
  </section>
));

// --- SbomLicenseMetrics Component ---
const SbomLicenseMetrics = React.memo(({ licenseTypes, totalPackages }) => {
  const metricColors = [
    CONFIG.COLORS.PURPLE.base,
    CONFIG.COLORS.CYAN.base,
    CONFIG.COLORS.INDIGO.base,
    CONFIG.COLORS.VIVIOLET.base
  ];

  return (
    <article className={styles.panelCard}>
      <h3>License Metrics</h3>
      <p className="mb-4 text-xs text-[var(--muted)]">Top license categories by package share</p>
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-5">
        {licenseTypes.slice(0, 4).map((item, idx) => {
          const percentage = totalPackages > 0 ? Math.round((item.value / totalPackages) * 100) : 0;
          return (
            <MetricBar
              key={idx}
              label={item.name}
              percentage={percentage}
              color={metricColors[idx % metricColors.length]}
            />
          );
        })}
      </div>
    </article>
  );
});

// --- License Helper Functions ---
const getLicenseInfo = (licenseConcluded) => {
  if (!licenseConcluded || licenseConcluded === "UNKNOWN" || licenseConcluded === "Unknown") {
    return LICENSE_POLICY_MAP.NOASSERTION || {
      category: "Unknown",
      riskLevel: "High",
      approvalStatus: "Legal-Review-Required",
      usageRules: "License not declared - requires manual review and legal assessment"
    };
  }

  if (licenseConcluded.includes(' AND ')) {
    const licenses = licenseConcluded.split(' AND ');
    const licenseInfos = licenses.map(license => LICENSE_POLICY_MAP[license.trim()]).filter(Boolean);
    if (licenseInfos.length === 0) return LICENSE_POLICY_MAP.NOASSERTION;

    const riskOrder = { 'High': 3, 'Medium': 2, 'Low': 1, 'Variable': 2 };
    return licenseInfos.sort((a, b) => riskOrder[b.riskLevel] - riskOrder[a.riskLevel])[0];
  }

  return LICENSE_POLICY_MAP[licenseConcluded] || LICENSE_POLICY_MAP.NOASSERTION || {
    category: "Unknown",
    riskLevel: "High",
    approvalStatus: "Legal-Review-Required",
    usageRules: "License not declared - requires manual review and legal assessment"
  };
};

const normalizeSeverity = (severity, fallback = "") => {
  if (!severity) return fallback;
  const normalized = String(severity).trim().toLowerCase();
  if (!normalized) return fallback;

  if (normalized === "critical") return "Critical";
  if (normalized === "high") return "High";
  if (normalized === "medium") return "Medium";
  if (normalized === "low") return "Low";
  return fallback;
};

const getDisplayRiskLevel = (pkg) => {
  const severityRisk = normalizeSeverity(pkg?.severity);
  if (severityRisk) return severityRisk;
  return getLicenseInfo(pkg?.licenseConcluded).riskLevel;
};

const toFiniteNumber = (value, fallback = 0) => {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
};

const getScoreColor = (score) => {
  if (score >= 90) return "#22C55E";
  if (score >= 70) return "#F59E0B";
  return "#EF4444";
};

const formatDate = (dateString) => {
  if (!dateString) return "N/A";
  const date = new Date(dateString);
  if (Number.isNaN(date.getTime())) return "N/A";
  return date.toLocaleDateString();
};

const formatDateTime = (dateString) => {
  if (!dateString) return "N/A";
  const date = new Date(dateString);
  if (Number.isNaN(date.getTime())) return "N/A";
  return date.toLocaleString(undefined, {
    day: "2-digit",
    month: "long",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
};

const formatLicenseName = (licenseConcluded) => {
  if (!licenseConcluded || licenseConcluded === "UNKNOWN" || licenseConcluded === "Unknown") {
    return "Unknown License";
  }
  return licenseConcluded;
};

const getPaginationPages = (current, total) => {
  if (total <= 7) return Array.from({ length: total }, (_, i) => i + 1);
  if (current <= 4) return [1, 2, 3, 4, 5, "...", total];
  if (current >= total - 3) return [1, "...", total - 4, total - 3, total - 2, total - 1, total];
  return [1, "...", current - 1, current, current + 1, "...", total];
};

// --- RiskBadge Component ---
const RiskBadge = ({ riskLevel }) => {
  const Icon = getSeverityIcon(riskLevel);

  return (
    <div
      className="inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider"
      style={getSeverityBadgeStyle(riskLevel)}
    >
      <Icon className="h-3 w-3" />
      {formatSeverityLabel(riskLevel)}
    </div>
  );
};

// --- SbomMainTable Component ---
const SbomMainTable = React.memo(({
  filteredAndSortedPackages,
  searchTerm,
  setSearchTerm,
  setCurrentPage,
  currentPage,
  totalPages,
  itemsPerPage,
  packageManagerFilter,
  setPackageManagerFilter,
  uniquePackageManagers,
  paginatedPackages
}) => {
  const tableRef = useRef(null);
  const [managerDropdownOpen, setManagerDropdownOpen] = useState(false);

  useEffect(() => {
    const handleClickOutside = (event) => {
      if (!event.target.closest('.manager-dropdown')) {
        setManagerDropdownOpen(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  useInteractiveTable({
    containerRef: tableRef,
    storageKey: "scanops-sbom-legacy-table",
    minWidth: 96,
    deps: [paginatedPackages.length, currentPage, totalPages],
  });

  return (
    <section className={styles.findingsShell}>
      <div className={styles.findingsHead}>
        <div>
          <h2>SBOM Dependencies</h2>
          <p>
            {filteredAndSortedPackages.length > 0
              ? `${(currentPage - 1) * itemsPerPage + 1}-${Math.min(currentPage * itemsPerPage, filteredAndSortedPackages.length)} of ${filteredAndSortedPackages.length}`
              : `0 of ${filteredAndSortedPackages.length}`} packages
          </p>
        </div>
        <div className="flex w-full flex-col gap-2 sm:w-auto sm:flex-row sm:items-center">
          <label className={styles.searchBox}>
            <Search size={15} />
            <input
              type="text"
              placeholder="Search packages, versions, links..."
              value={searchTerm}
              onChange={(e) => {
                setSearchTerm(e.target.value);
                setCurrentPage(1);
              }}
            />
          </label>

          <div className="relative manager-dropdown">
            <button
              type="button"
              onClick={() => setManagerDropdownOpen((v) => !v)}
              className={`inline-flex items-center gap-2 rounded-lg border px-3.5 py-1.5 text-xs font-normal transition-colors shadow-sm ${
                packageManagerFilter !== "all"
                  ? "border-primary/40 bg-primary/10 text-primary font-medium"
                  : "border-default bg-surface text-muted hover:border-hover hover:text-text"
              }`}
            >
              <span>
                Manager:{" "}
                <strong className="font-medium text-text">
                  {packageManagerFilter === "all" ? "All" : packageManagerFilter}
                </strong>
              </span>
              <ChevronDown className={`h-3.5 w-3.5 text-muted transition-transform ${managerDropdownOpen ? "rotate-180" : ""}`} />
            </button>

            {managerDropdownOpen && (
              <div className="absolute right-0 top-full mt-1.5 w-48 overflow-hidden rounded-xl border border-default bg-surface shadow-xl z-50 py-1">
                <div className="flex items-center justify-between border-b border-default bg-surface px-3.5 py-2">
                  <button
                    type="button"
                    onClick={() => {
                      setPackageManagerFilter("all");
                      setCurrentPage(1);
                      setManagerDropdownOpen(false);
                    }}
                    className="text-xs text-primary hover:underline font-medium"
                  >
                    Select All
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setPackageManagerFilter("all");
                      setCurrentPage(1);
                      setManagerDropdownOpen(false);
                    }}
                    className="text-xs text-muted hover:text-text"
                  >
                    Clear
                  </button>
                </div>
                <button
                  type="button"
                  onClick={() => {
                    setPackageManagerFilter("all");
                    setCurrentPage(1);
                    setManagerDropdownOpen(false);
                  }}
                  className="w-full flex items-center justify-between px-3.5 py-2 text-xs hover:bg-elevated text-left text-text transition-colors"
                >
                  <span>All managers</span>
                  {packageManagerFilter === "all" && <Check className="h-3.5 w-3.5 text-primary shrink-0 ml-2" />}
                </button>
                {uniquePackageManagers.map((manager) => (
                  <button
                    key={manager}
                    type="button"
                    onClick={() => {
                      setPackageManagerFilter(manager);
                      setCurrentPage(1);
                      setManagerDropdownOpen(false);
                    }}
                    className="w-full flex items-center justify-between px-3.5 py-2 text-xs hover:bg-elevated text-left text-text transition-colors"
                  >
                    <span className="truncate">{manager}</span>
                    {packageManagerFilter === manager && <Check className="h-3.5 w-3.5 text-primary shrink-0 ml-2" />}
                  </button>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>

      <div className={styles.findingsList} style={{ padding: 0, maxHeight: "620px" }}>
        <div className="overflow-x-auto" ref={tableRef}>
          <table className="w-full min-w-[1120px] table-fixed">
            <colgroup>
              <col style={{ width: "30%" }} />
              <col style={{ width: "14%" }} />
              <col style={{ width: "20%" }} />
              <col style={{ width: "18%" }} />
              <col style={{ width: "18%" }} />
            </colgroup>
            <thead className="border-b border-default figma-table-head bg-[var(--table-head-bg)]">
              <tr>
                <th className="px-6 py-3.5 text-center text-xs font-semibold text-text">Package</th>
                <th className="px-4 py-3.5 text-center text-xs font-semibold text-text">Version</th>
                <th className="px-4 py-3.5 text-center text-xs font-semibold text-text">License</th>
                <th className="px-4 py-3.5 text-center text-xs font-semibold text-text">Risk</th>
                <th className="px-4 py-3.5 text-center text-xs font-semibold text-text">Link</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-default">
              {paginatedPackages.map((pkg, i) => {
                const isUnknownLicense = !pkg.licenseConcluded || pkg.licenseConcluded === "UNKNOWN" || pkg.licenseConcluded.toLowerCase() === "other";

                const getLicenseDisplayColor = () => {
                  const licenseText = (pkg.licenseConcluded || "").toLowerCase();
                  if (isUnknownLicense) return "var(--warning)";
                  if (licenseText.includes('apache')) return "var(--info)";
                  if (licenseText.includes('bsd')) return "var(--color-primary)";
                  if (licenseText.includes('mit')) return "var(--success)";
                  return "var(--success)";
                };

                const licenseInfo = getLicenseInfo(pkg.licenseConcluded);
                const displayRiskLevel = getDisplayRiskLevel(pkg);
                return (
                  <tr key={i} className="group transition-colors hover:bg-elevated/40 border-b border-default">
                    <td className="px-6 py-4 text-left">
                      <div className="flex items-center justify-start gap-3">
                        <span className="inline-flex h-8 w-8 items-center justify-center rounded-lg bg-[color-mix(in_srgb,var(--color-primary)_10%,transparent)]">
                          <Package className="h-4 w-4 text-[var(--color-primary)]" />
                        </span>
                        <span className="max-w-[340px] truncate text-sm font-bold text-[var(--text)]">{pkg.moduleName}</span>
                      </div>
                    </td>

                    <td className="px-4 py-4 text-left">
                      <span className="inline-flex items-center justify-start rounded-md border border-[var(--border)] bg-[var(--elevated-surface)] px-2.5 py-1 font-mono text-[11px] text-[var(--info)]">
                        {pkg.versionInfo || "-"}
                      </span>
                    </td>

                    <td className="px-4 py-4 text-left">
                      <span className="text-sm font-semibold text-left" style={{ color: getLicenseDisplayColor() }}>
                        {formatLicenseName(pkg.licenseConcluded) || "Unknown"}
                      </span>
                    </td>

                    <td className="px-4 py-4 text-left">
                      <Tooltip
                        title={
                          <div className="p-3 space-y-3 max-w-[300px] text-[var(--text)]">
                            <div className="flex flex-col gap-1.5">
                              <div className="flex items-center gap-2">
                                <Tag size={14} className="text-[var(--color-primary)]" />
                                <span className="text-[10px] font-bold uppercase text-[var(--muted)] tracking-wider">Category</span>
                              </div>
                              <span className="text-xs font-semibold pl-5.5">{licenseInfo.category}</span>
                            </div>

                            <div className="flex flex-col gap-1.5">
                              <div className="flex items-center gap-2">
                                <ShieldCheck size={14} className="text-[var(--success)]" />
                                <span className="text-[10px] font-bold uppercase text-[var(--muted)] tracking-wider">Approval Status</span>
                              </div>
                              <span className="text-xs font-semibold pl-5.5">{licenseInfo.approvalStatus}</span>
                            </div>

                            <div className="flex flex-col gap-1.5">
                              <div className="flex items-center gap-2">
                                <FileText size={14} className="text-[var(--info)]" />
                                <span className="text-[10px] font-bold uppercase text-[var(--muted)] tracking-wider">Usage Rules</span>
                              </div>
                              <p className="text-[11px] text-[var(--text-secondary)] leading-relaxed font-sans pl-5.5">{licenseInfo.usageRules}</p>
                            </div>
                          </div>
                        }
                        slotProps={{
                          tooltip: {
                            sx: {
                              backdropFilter: "blur(12px)",
                              background: "var(--glass-bg) !important",
                              border: "1px solid var(--border)",
                              borderRadius: "12px",
                              padding: "0",
                              boxShadow: "var(--shadow-2)",
                              "& .MuiTooltip-arrow": {
                                color: "var(--glass-bg)",
                              }
                            }
                          }
                        }}
                        arrow
                        placement="top"
                      >
                        <div className="cursor-help inline-flex justify-start">
                          <RiskBadge riskLevel={displayRiskLevel} />
                        </div>
                      </Tooltip>
                    </td>

                    <td className="px-4 py-4 text-left">
                      {pkg.packageURL ? (
                        <a href={pkg.packageURL} target="_blank" rel="noopener noreferrer" className="inline-flex items-center justify-start gap-1.5 hover:opacity-80 transition-opacity text-[var(--info)]">
                          <ExternalLink className="w-4 h-4" />
                          <span className="text-xs font-sans">View</span>
                        </a>
                      ) : (
                        <span className="text-[var(--muted)]">—</span>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>

          {paginatedPackages.length === 0 && (
            <div className={styles.emptyResult} style={{ margin: "16px" }}>
              No dependencies found matching the current filters.
            </div>
          )}
        </div>
      </div>
    </section>
  );
});

// --- SbomPagination Component ---
const SbomPagination = React.memo(({ currentPage, totalPages, setCurrentPage, itemsPerPage, totalFilteredCount }) => {
  if (totalPages <= 1) return null;

  return (
    <article className={`${styles.panelCard} !p-0 overflow-hidden`}>
      <TablePagination
        currentPage={currentPage}
        totalPages={totalPages}
        totalItems={totalFilteredCount}
        pageSize={itemsPerPage}
        setCurrentPage={setCurrentPage}
      />
    </article>
  );
});

// --- Main Sbom Component ---
const Sbom = () => {
  const { latestScan, loading, error } = useScanStore();

  if (loading) return <LoadingState />;
  if (error) return <ErrorState error={error} />;
  if (!latestScan) return <EmptyState title="Scan Not Initiated" message="Start a new scan to find issues." />;

  function normalizeUnknown(value, fallback = "Unknown") {
    if (value === null || value === undefined) return fallback;
    const normalized = String(value).trim();
    if (!normalized || normalized.toLowerCase() === "unknown") return fallback;
    return normalized;
  }

  function normalizePackageUrl(value) {
    if (!value) return "";
    const normalized = String(value).trim();
    if (!normalized || normalized.toLowerCase() === "unknown") return "";
    return normalized;
  }

  // Extract SBOM data from the scan results
  const sbomData = useMemo(() => {
    const sbomResults = latestScan?.scan_results?.scans_findings?.["Sbom-findings"] || [];
    const severityByModule = new Map(
      sbomResults.flatMap((result) => {
        const findings = result?.violated_policies || [];
        return findings.map((finding) => {
          const moduleName = normalizeUnknown(finding.Matches || extractModuleName(finding.description));
          return [moduleName, normalizeSeverity(finding.severity, "Medium")];
        });
      })
    );

    const dependencyData = latestScan?.scan_results?.scan_results?.scanner_results?.sbom?.metadata?.dependencies;
    if (Array.isArray(dependencyData) && dependencyData.length > 0) {
      return dependencyData.map((dep) => ({
        moduleName: normalizeUnknown(dep.moduleName),
        versionInfo: normalizeUnknown(dep.versionInfo),
        licenseConcluded: normalizeUnknown(dep.licenseConcluded),
        packageManager: normalizeUnknown(dep.packageManager),
        packageURL: normalizePackageUrl(dep.packageURL),
        sourceLocation: normalizeUnknown(dep.sourceLocation, ""),
        severity: normalizeSeverity(severityByModule.get(normalizeUnknown(dep.moduleName)), "Medium")
      }));
    }

    if (!Array.isArray(sbomResults) || sbomResults.length === 0) return [];

    // Fallback: transform finding descriptions into package rows.
    return sbomResults.flatMap((result) => {
      const packages = result.violated_policies || [];
      return packages.map((pkg) => ({
        moduleName: normalizeUnknown(pkg.Matches || extractModuleName(pkg.description)),
        versionInfo: normalizeUnknown(extractVersion(pkg.description)),
        licenseConcluded: normalizeUnknown(extractLicense(pkg.description)),
        packageManager: normalizeUnknown(extractPackageManager(pkg.description)),
        packageURL: normalizePackageUrl(pkg.remediation),
        sourceLocation: normalizeUnknown(result.file_name, ""),
        severity: normalizeSeverity(pkg.severity, "Medium")
      }));
    });
  }, [latestScan]);

  const sbomScanner = useMemo(() => {
    return latestScan?.scan_results?.scan_results?.scanner_results?.sbom || null;
  }, [latestScan]);

  const scanMetadata = latestScan?.scan_metadata || {};
  const scanTime = scanMetadata.scan_timestamp || scanMetadata.created_at;
  const securityScore = toFiniteNumber(
    latestScan?.scan_results?.scan_results?.summary?.score_summary?.score_by_subscan?.sbom,
    0
  );
  const boundedScore = Math.max(0, Math.min(100, Math.round(securityScore)));
  const scoreColor = getScoreColor(boundedScore);
  const ringRadius = 42;
  const ringCircumference = 2 * Math.PI * ringRadius;
  const ringOffset = ringCircumference * (1 - boundedScore / 100);
  const metadataCards = [
    {
      label: "Last Commit",
      value: scanMetadata.repository || scanMetadata.repo_name || "N/A",
      icon: GitCommitHorizontal,
    },
    {
      label: "Commit Author",
      value: String(scanMetadata.commit_author ?? scanMetadata.author ?? "").trim() || "N/A",
      icon: User,
    },
    {
      label: "Commit",
      value: scanMetadata.commit_message || "N/A",
      icon: GitCompare,
    },
    {
      label: "Scan Date",
      value: formatDate(scanTime),
      icon: Calendar,
    },
  ];

  // Helper functions to parse the description string
  function extractModuleName(description) {
    const match = description?.match(/Package:\s*([^\s|]+)/);
    return match ? match[1] : "Unknown";
  }

  function extractVersion(description) {
    const match = description?.match(/\bv([^\s|]+)/);
    return match ? match[1] : "Unknown";
  }

  function extractLicense(description) {
    const match = description?.match(/License:\s*([^\s|]+)/);
    const license = match ? match[1] : "Unknown";
    if (license === "Unknown" || license === "UNKNOWN") return "Unknown";
    return license;
  }

  function extractPackageManager(description) {
    const match = description?.match(/Manager:\s*([^\s|]+)/);
    return match ? match[1] : null;
  }

  const [currentPage, setCurrentPage] = useState(1);
  const [searchTerm, setSearchTerm] = useState("");
  const [licenseFilter, setLicenseFilter] = useState("all");
  const [packageManagerFilter, setPackageManagerFilter] = useState("all");
  const [languageFilter, setLanguageFilter] = useState("all");
  const [riskLevelFilter, setRiskLevelFilter] = useState("all");
  const [approvalStatusFilter, setApprovalStatusFilter] = useState("all");
  const [sortConfig, setSortConfig] = useState({ key: null, direction: "asc" });
  const [viewMode, setViewMode] = useState("table");

  // Reset to page 1 when filters change
  useEffect(() => {
    setCurrentPage(1);
  }, [searchTerm, licenseFilter, packageManagerFilter, languageFilter, riskLevelFilter, approvalStatusFilter]);

  // Chart colors from root schema using dynamic CSS variables
  const chartColors = useMemo(() => ({
    primary: 'var(--color-primary)',
    secondary: 'var(--color-secondary)',
    accent: 'var(--color-accent)',
    success: 'var(--success)',
    danger: 'var(--danger)',
    warning: 'var(--warning)',
    info: 'var(--info)',
    muted: 'var(--muted)'
  }), []);

  const CHART_SERIES = useMemo(() => [
    chartColors.primary,
    chartColors.secondary,
    chartColors.accent,
    chartColors.success,
    chartColors.danger,
    chartColors.warning,
    chartColors.info
  ], [chartColors]);

  // Use sbomData instead of packages
  const packages = sbomData;

  const uniqueLicenses = useMemo(() => {
    const fromMetadata = sbomScanner?.metadata?.licenses;
    if (Array.isArray(fromMetadata) && fromMetadata.length > 0) return [...fromMetadata].sort();
    return [...new Set(packages.map((p) => p.licenseConcluded).filter(Boolean))].sort();
  }, [packages, sbomScanner]);

  const uniquePackageManagers = useMemo(() => {
    const fromMetadata = sbomScanner?.metadata?.package_managers;
    if (Array.isArray(fromMetadata) && fromMetadata.length > 0) return [...fromMetadata].sort();
    return [...new Set(packages.map((p) => p.packageManager).filter(Boolean))].sort();
  }, [packages, sbomScanner]);

  const uniqueLanguages = useMemo(() => {
    return [...new Set(packages.map(p => p.packageManager).filter(Boolean))];
  }, [packages]);

  const uniqueRiskLevels = useMemo(() => {
    const riskLevels = [...new Set(packages.map(pkg => {
      return getDisplayRiskLevel(pkg);
    }))];
    return riskLevels.sort();
  }, [packages]);

  const uniqueApprovalStatuses = useMemo(() => {
    const statuses = [...new Set(packages.map(pkg => {
      const licenseInfo = getLicenseInfo(pkg.licenseConcluded);
      return licenseInfo.approvalStatus;
    }))];
    return statuses.sort();
  }, [packages]);

  const complianceStats = useMemo(() => {
    const unknownFromMeta = sbomScanner?.metadata?.unknown_licenses_count;
    const stats = {
      total: sbomScanner?.metadata?.total_packages ?? packages.length,
      preApproved: 0,
      reviewRequired: 0,
      legalReviewRequired: 0,
      highRisk: 0,
      mediumRisk: 0,
      lowRisk: 0,
      unknown: unknownFromMeta ?? 0,
    };

    packages.forEach(pkg => {
      const licenseInfo = getLicenseInfo(pkg.licenseConcluded);
      const displayRiskLevel = getDisplayRiskLevel(pkg);

      if (unknownFromMeta === undefined && (!pkg.licenseConcluded || pkg.licenseConcluded === "Unknown")) {
        stats.unknown++;
      }

      switch (licenseInfo.approvalStatus) {
        case 'Pre-approved':
          stats.preApproved++;
          break;
        case 'Review-Required':
          stats.reviewRequired++;
          break;
        case 'Legal-Review-Required':
        case 'Purchase-Legal-Review':
        case 'Legal-IT-Approval':
          stats.legalReviewRequired++;
          break;
      }

      switch (displayRiskLevel) {
        case 'Low':
          stats.lowRisk++;
          break;
        case 'Medium':
          stats.mediumRisk++;
          break;
        case 'Critical':
        case 'High':
          stats.highRisk++;
          break;
      }
    });

    return stats;
  }, [packages, sbomScanner]);



  const chartData = useMemo(() => {
    const riskDistributionData = [
      { name: 'Low Risk', value: complianceStats.lowRisk, color: 'var(--success)' },
      { name: 'Medium Risk', value: complianceStats.mediumRisk, color: 'var(--warning)' },
      { name: 'High Risk', value: complianceStats.highRisk, color: 'var(--danger)' },
      { name: 'Unknown', value: complianceStats.unknown, color: 'var(--muted)' }
    ];

    const approvalStatusData = [
      { name: 'Pre-approved', value: complianceStats.preApproved, color: 'var(--success)' },
      { name: 'Review Required', value: complianceStats.reviewRequired, color: 'var(--warning)' },
      { name: 'Legal Review', value: complianceStats.legalReviewRequired, color: 'var(--danger)' }
    ];

    const licenseTypeData = packages.reduce((acc, pkg) => {
      const licenseInfo = getLicenseInfo(pkg.licenseConcluded);
      const category = licenseInfo.category || 'Unknown';
      acc[category] = (acc[category] || 0) + 1;
      return acc;
    }, {});

    const licenseTypeChartData = Object.entries(licenseTypeData).map(([name, value], index) => ({
      name,
      value,
      color: CHART_SERIES[index % CHART_SERIES.length]
    }));

    const packageManagerData = packages.reduce((acc, pkg) => {
      const manager = pkg.packageManager || 'Unknown';
      acc[manager] = (acc[manager] || 0) + 1;
      return acc;
    }, {});

    const packageManagerChartData = Object.entries(packageManagerData)
      .sort(([, a], [, b]) => b - a)
      .slice(0, 8)
      .map(([name, value], index) => ({
        name,
        value,
        color: CHART_SERIES[index % CHART_SERIES.length]
      }));

    return {
      riskDistribution: riskDistributionData.filter(item => item.value > 0),
      approvalStatus: approvalStatusData.filter(item => item.value > 0),
      licenseTypes: licenseTypeChartData.filter(item => item.value > 0),
      packageManagers: packageManagerChartData
    };
  }, [packages, complianceStats]);

  const filteredAndSortedPackages = useMemo(() => {
    let filtered = packages.filter((pkg) => {
      const matchesSearch =
        pkg.moduleName?.toLowerCase().includes(searchTerm.toLowerCase()) ||
        pkg.versionInfo?.toLowerCase().includes(searchTerm.toLowerCase()) ||
        pkg.packageURL?.toLowerCase().includes(searchTerm.toLowerCase());

      const matchesLicense =
        licenseFilter === "all" ||
        (licenseFilter === "Unknown"
          ? (!pkg.licenseConcluded || pkg.licenseConcluded === "Unknown")
          : pkg.licenseConcluded === licenseFilter);

      const matchesPackageManager =
        packageManagerFilter === "all" ||
        pkg.packageManager === packageManagerFilter;

      const matchesLanguage = languageFilter === "all" ||
        pkg.packageManager === languageFilter;

      const licenseInfo = getLicenseInfo(pkg.licenseConcluded);
      const matchesRiskLevel = riskLevelFilter === "all" || getDisplayRiskLevel(pkg) === riskLevelFilter;
      const matchesApprovalStatus = approvalStatusFilter === "all" || licenseInfo.approvalStatus === approvalStatusFilter;

      return matchesSearch && matchesLicense && matchesPackageManager && matchesLanguage && matchesRiskLevel && matchesApprovalStatus;
    });

    if (sortConfig.key) {
      filtered.sort((a, b) => {
        let aVal = a[sortConfig.key] || '';
        let bVal = b[sortConfig.key] || '';

        if (sortConfig.key === 'riskLevel' || sortConfig.key === 'approvalStatus') {
          const aLicenseInfo = getLicenseInfo(a.licenseConcluded);
          const bLicenseInfo = getLicenseInfo(b.licenseConcluded);
          aVal = sortConfig.key === 'riskLevel' ? getDisplayRiskLevel(a) : aLicenseInfo.approvalStatus;
          bVal = sortConfig.key === 'riskLevel' ? getDisplayRiskLevel(b) : bLicenseInfo.approvalStatus;
        }

        if (aVal < bVal) {
          return sortConfig.direction === "asc" ? -1 : 1;
        }
        if (aVal > bVal) {
          return sortConfig.direction === "asc" ? 1 : -1;
        }
        return 0;
      });
    }

    return filtered;
  }, [packages, searchTerm, licenseFilter, packageManagerFilter, languageFilter, riskLevelFilter, approvalStatusFilter, sortConfig]);

  const ITEMS_PER_PAGE = viewMode === "table" ? CONFIG.LAYOUT.TABLE_ITEMS_PER_PAGE : CONFIG.LAYOUT.GRID_ITEMS_PER_PAGE;
  const totalPages = Math.ceil(filteredAndSortedPackages.length / ITEMS_PER_PAGE);
  const paginatedPackages = filteredAndSortedPackages.slice(
    (currentPage - 1) * ITEMS_PER_PAGE,
    currentPage * ITEMS_PER_PAGE
  );

  if (packages.length === 0) return <EmptyState />;

  return (
    <div className={styles.pageRoot}>
      <main className={styles.contentWrap}>
        <ScanMetadataOverview
          scanMetadata={scanMetadata}
          scanType="SBOM"
          duration={formatDateTime(scanTime)}
        />

        <SbomRiskCharts
          licenseTypes={chartData.licenseTypes}
          packageManagers={chartData.packageManagers}
          score={boundedScore}
        />

        <SbomLicenseMetrics
          licenseTypes={chartData.licenseTypes}
          totalPackages={packages.length}
        />

        <SbomMainTable
          filteredAndSortedPackages={filteredAndSortedPackages}
          searchTerm={searchTerm}
          setSearchTerm={setSearchTerm}
          setCurrentPage={setCurrentPage}
          currentPage={currentPage}
          totalPages={totalPages}
          itemsPerPage={ITEMS_PER_PAGE}
          packageManagerFilter={packageManagerFilter}
          setPackageManagerFilter={setPackageManagerFilter}
          uniquePackageManagers={uniquePackageManagers}
          paginatedPackages={paginatedPackages}
        />

        <SbomPagination
          currentPage={currentPage}
          totalPages={totalPages}
          setCurrentPage={setCurrentPage}
          itemsPerPage={ITEMS_PER_PAGE}
          totalFilteredCount={filteredAndSortedPackages.length}
        />
      </main>
    </div>
  );
};

export default Sbom;