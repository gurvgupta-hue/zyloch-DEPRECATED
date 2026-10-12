"use client";

import React, { useEffect, useMemo, useRef, useState } from "react";
import dynamic from "next/dynamic";
import { useScanStore } from "@/store/useScanStore";
import LoadingState from "./LoadingState";
import ErrorState from "./ErrorState";
import EmptyState from "./EmptyState";
import {
  AlertTriangle,
  Calendar,
  FileText,
  GitCommitHorizontal,
  GitCompare,
  Search,
  ShieldCheck,
  User,
  ChevronLeft,
  ChevronRight,
  Eye,
  ChevronDown,
  X,
  Check,
  Filter,
} from "lucide-react";
import { formatApiText } from "./utils";
import { formatChartLabel } from "@/components/charts/labelFormatter";
import styles from "./Workflow.module.css";
import TechStackIcon from "@/components/common/TechStackIcon";
import TablePagination from "../shared/TablePagination";
import {
  getSeverityBadgeStyle as getSharedSeverityBadgeStyle,
  getSeverityIcon as getSharedSeverityIcon,
  getSeverityColorToken,
  SEVERITY_FIGMA_COLORS,
  TableSeverityBadge,
} from "../shared/severityVisuals";
import { useInteractiveTable } from "../shared/useInteractiveTable";
import IssuesBySeverityCard from "../shared/IssuesBySeverityCard";
import SecurityScoreCard from "../shared/SecurityScoreCard";
import ScanMetadataOverview from "../shared/ScanMetadataOverview";
const BarChartUI = dynamic(() => import("@/components/charts/BarChartUI"), {
  ssr: false,
  loading: () => <div className={styles.chartLoading}>Loading Chart...</div>,
});

const PieChartUI = dynamic(() => import("@/components/charts/PieChartUI"), {
  ssr: false,
  loading: () => <div className={styles.chartLoading}>Loading Chart...</div>,
});

const SEVERITY_ORDER = ["critical", "high", "medium", "low"];
const PAGE_SIZE_OPTIONS = [10, 25, 50, 100];

const getPaginationPages = (current, total) => {
  if (total <= 7) return Array.from({ length: total }, (_, i) => i + 1);
  if (current <= 4) return [1, 2, 3, 4, 5, "…", total];
  if (current >= total - 3) return [1, "…", total - 4, total - 3, total - 2, total - 1, total];
  return [1, "…", current - 1, current, current + 1, "…", total];
};

const Workflow = () => {
  const { latestScan, loading, error } = useScanStore();
  const [query, setQuery] = useState("");
  const [selectedSeverities, setSelectedSeverities] = useState(SEVERITY_ORDER);
  const [selectedPolicies, setSelectedPolicies] = useState(null); // null = all
  const [severityDropdownOpen, setSeverityDropdownOpen] = useState(false);
  const [policyDropdownOpen, setPolicyDropdownOpen] = useState(false);
  const [currentPage, setCurrentPage] = useState(1);
  const [pageSize, setPageSize] = useState(25);
  const tableRef = useRef(null);

  if (loading) return <LoadingState />;
  if (error) return <ErrorState error={error} />;

  if (!latestScan) {
    return <EmptyState title="Scan Not Initiated" message="Start a new scan to find issues." />;
  }

  const scanResults = latestScan?.scan_results || {};
  const workflowFindingsRaw = scanResults?.scans_findings?.["Workflow-findings"];
  const workflowFindings = Array.isArray(workflowFindingsRaw)
    ? workflowFindingsRaw
    : [];

  if (!workflowFindings.length) {
    return <EmptyState />;
  }

  const summary = scanResults?.scan_results?.summary || {};
  const workflowSummary =
    summary?.issues_summary?.issue_counts_by_subscan_and_severity?.workflow || {};

  const scanMetadata = latestScan.scan_metadata;
  const securityScore = toFiniteNumber(
    summary?.score_summary?.score_by_subscan?.workflow,
    0
  );
  const boundedScore = Math.max(0, Math.min(100, Math.round(securityScore)));
  const scoreColor = getScoreColor(boundedScore);
  const ringRadius = 42;
  const ringCircumference = 2 * Math.PI * ringRadius;
  const ringOffset = ringCircumference * (1 - boundedScore / 100);

  const severityData = SEVERITY_ORDER.map((key) => ({
    name: formatApiText(key),
    value: toFiniteNumber(workflowSummary[key], 0),
    color: getSeverityColor(key),
  }));

  const policyData = workflowFindings.reduce((acc, finding) => {
    const policies = Array.isArray(finding?.violated_policies)
      ? finding.violated_policies
      : [];

    policies.forEach((policy) => {
      const policyCode = policy?.policy_code;
      if (!policyCode) return;
      acc[policyCode] = (acc[policyCode] || 0) + 1;
    });
    return acc;
  }, {});

  const pieChartData = Object.entries(policyData)
    .map(([policy, count]) => ({
      name: formatChartLabel(policy),
      value: toFiniteNumber(count, 0),
      color: getPolicyColor(policy),
    }))
    .filter((item) => item.value > 0);

  const severityCounts = useMemo(() => {
    const counts = { critical: 0, high: 0, medium: 0, low: 0 };
    workflowFindings.forEach((finding) => {
      const policies = Array.isArray(finding?.violated_policies)
        ? finding.violated_policies
        : [];
      policies.forEach((policy) => {
        const sev = String(policy?.severity || "").trim().toLowerCase();
        if (counts[sev] !== undefined) {
          counts[sev] += 1;
        }
      });
    });
    return counts;
  }, [workflowFindings]);

  const policyOptions = useMemo(() => {
    const set = new Set();
    workflowFindings.forEach((finding) => {
      (finding?.violated_policies || []).forEach((policy) => {
        const code = String(policy?.policy_code || "").trim();
        if (code) set.add(code);
      });
    });
    return Array.from(set).sort((a, b) => a.localeCompare(b));
  }, [workflowFindings]);

  useEffect(() => {
    const handleClickOutside = (event) => {
      if (
        !event.target.closest(".workflow-severity-dropdown") &&
        !event.target.closest(".workflow-policy-dropdown")
      ) {
        setSeverityDropdownOpen(false);
        setPolicyDropdownOpen(false);
      }
    };

    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);

  const toggleSeverity = (sev) => {
    setSelectedSeverities((prev) =>
      prev.includes(sev) ? prev.filter((s) => s !== sev) : [...prev, sev]
    );
    setCurrentPage(1);
  };
  const selectAllSeverities = () => {
    setSelectedSeverities(SEVERITY_ORDER);
    setCurrentPage(1);
  };
  const clearAllSeverities = () => {
    setSelectedSeverities([]);
    setCurrentPage(1);
  };

  const togglePolicy = (policy) => {
    const current = selectedPolicies ?? policyOptions;
    const next = current.includes(policy) ? current.filter((p) => p !== policy) : [...current, policy];
    setSelectedPolicies(next.length === policyOptions.length ? null : next);
    setCurrentPage(1);
  };
  const selectAllPolicies = () => {
    setSelectedPolicies(null);
    setCurrentPage(1);
  };
  const clearAllPolicies = () => {
    setSelectedPolicies([]);
    setCurrentPage(1);
  };

  const hasPartialSeverity = selectedSeverities.length > 0 && selectedSeverities.length < SEVERITY_ORDER.length;
  const hasAllSeverities = selectedSeverities.length === SEVERITY_ORDER.length;

  const hasAllPolicies = selectedPolicies === null || selectedPolicies.length === policyOptions.length;
  const hasPartialPolicies = selectedPolicies !== null && selectedPolicies.length > 0 && selectedPolicies.length < policyOptions.length;

  const hasActiveFilters =
    query.trim() !== "" ||
    !hasAllSeverities ||
    !hasAllPolicies;

  const clearFilters = () => {
    setQuery("");
    setSelectedSeverities(SEVERITY_ORDER);
    setSelectedPolicies(null);
    setCurrentPage(1);
  };

  const filteredFindings = useMemo(() => {
    const normalizedQuery = query.trim().toLowerCase();
    const activePolicies = selectedPolicies ?? policyOptions;

    return workflowFindings
      .map((finding) => {
        let policies = Array.isArray(finding?.violated_policies)
          ? finding.violated_policies
          : [];

        if (!hasAllSeverities) {
          policies = policies.filter((policy) => {
            const sev = String(policy?.severity || "").trim().toLowerCase();
            return selectedSeverities.includes(sev);
          });
        }

        if (!hasAllPolicies) {
          policies = policies.filter((policy) => activePolicies.includes(policy?.policy_code));
        }

        if (normalizedQuery) {
          policies = policies.filter((policy) => {
            const fullText = [
              finding.file_name,
              policy?.policy_code,
              policy?.policy_name,
              policy?.description,
              policy?.severity,
            ]
              .filter(Boolean)
              .join(" ")
              .toLowerCase();

            return fullText.includes(normalizedQuery);
          });
        }

        return {
          ...finding,
          violated_policies: policies,
        };
      })
      .filter((finding) => finding.violated_policies.length > 0);
  }, [query, selectedSeverities, hasAllSeverities, selectedPolicies, hasAllPolicies, policyOptions, workflowFindings]);

  const totalVisibleIssues = filteredFindings.reduce(
    (acc, finding) => acc + finding.violated_policies.length,
    0
  );

  const totalIssues =
    summary?.issues_summary?.total_issues_by_subscan?.workflow ||
    Object.values(severityCounts).reduce((acc, val) => acc + val, 0);

  const tableRows = useMemo(() => {
    return filteredFindings.flatMap((finding, idx) =>
      (finding.violated_policies || []).map((policy, pIdx) => ({
        id: `${finding.file_name || "unknown"}-${policy?.policy_code || "policy"}-${idx}-${pIdx}`,
        file_name: finding.file_name || "N/A",
        line_no: policy?.Line_No && policy.Line_No !== "-" ? policy.Line_No : (policy?.line_no && policy.line_no !== "-" ? policy.line_no : "N/A"),
        policy_code: policy?.policy_code || "N/A",
        policy_name: policy?.policy_name || "N/A",
        severity: String(policy?.severity || "unknown").trim().toLowerCase(),
        description: cleanDescription(policy?.description || "N/A"),
        remediation: resolveRemediation(policy),
      }))
    );
  }, [filteredFindings]);

  useEffect(() => {
    setCurrentPage(1);
  }, [query, selectedSeverities, selectedPolicies, filteredFindings.length]);

  const totalPages = Math.max(1, Math.ceil(tableRows.length / pageSize));
  const safePage = Math.min(currentPage, totalPages);
  const pageStart = (safePage - 1) * pageSize;
  const pageEnd = Math.min(pageStart + pageSize, tableRows.length);
  const pagedTableRows = tableRows.slice(pageStart, pageEnd);

  useInteractiveTable({
    containerRef: tableRef,
    storageKey: "scanops-workflow-findings-table",
    minWidth: 88,
    deps: [pagedTableRows.length, currentPage, pageSize, query, selectedSeverities, selectedPolicies],
  });

  const goToPage = (page) => {
    const clamped = Math.max(1, Math.min(page, totalPages));
    setCurrentPage(clamped);
  };

  const metadataCards = [
    {
      label: "Last Commit",
      value: scanMetadata?.repository || "N/A",
      icon: GitCommitHorizontal,
    },
    {
      label: "Commit Author",
      value: String(scanMetadata?.commit_author ?? "").trim() || "N/A",
      icon: User,
    },
    {
      label: "Commit",
      value: scanMetadata?.commit_message || "N/A",
      icon: GitCompare,
    },
    {
      label: "Scan Date",
      value: formatDate(scanMetadata?.scan_timestamp),
      icon: Calendar,
    },
  ];



  return (
    <div className={styles.pageRoot}>
      <main className={styles.contentWrap}>
        <ScanMetadataOverview
          scanMetadata={scanMetadata}
          scanType="GITHUB ACTIONS WORKFLOW"
          duration={formatDate(scanMetadata?.scan_timestamp)}
        />

        <section className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-6 items-stretch">
          <SecurityScoreCard score={boundedScore} />
          <IssuesBySeverityCard severityCounts={severityCounts} />

          <div
            className="rounded-2xl border border-[var(--border)] bg-[var(--surface)] p-6 shadow-2 flex flex-col justify-between items-stretch hover:translate-y-[-2px] hover:shadow-xl transition-all duration-300"
            style={{ minHeight: "280px" }}
          >
            <div className="flex items-center justify-between gap-2 mb-2">
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
                Policy Distribution
              </h4>
              {pieChartData.length > 0 && (
                <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-semibold text-[var(--muted)] bg-[var(--elevated-surface)] border border-[var(--border)]">
                  <span>Policies:</span>
                  <strong className="text-[var(--text)] font-bold">{pieChartData.length}</strong>
                </span>
              )}
            </div>

            {pieChartData.length > 0 ? (
              <div className="flex flex-row items-center justify-between gap-6 w-full flex-grow overflow-hidden py-1">
                <div className="w-[160px] h-[160px] shrink-0 flex items-center justify-center">
                  <PieChartUI
                    data={pieChartData}
                    height={160}
                    innerRadius={50}
                    outerRadius={75}
                    showLegend={false}
                    showCenterText={false}
                  />
                </div>

                <div className="flex flex-col gap-2 flex-grow min-w-0 max-h-[180px] overflow-y-auto pr-1">
                  {pieChartData.map((item, idx) => (
                    <div
                      key={`${item.name}-${idx}`}
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
              <div className="flex flex-col items-center justify-center flex-grow py-8 text-muted text-xs">
                No policy distribution data available
              </div>
            )}
          </div>
        </section>

        <section className={styles.findingsShell}>
          <div className={styles.findingsHead}>
            <div>
              <h2>GITHUB ACTIONS WORKFLOW Findings</h2>
              <p>
                {totalVisibleIssues} issues shown in {filteredFindings.length} file
                {filteredFindings.length === 1 ? "" : "s"}
              </p>
            </div>

            <label className={styles.searchBox}>
              <Search size={16} />
              <input
                type="text"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Search findings, files, or policies..."
              />
            </label>
          </div>

          <div className="flex flex-wrap items-center gap-3 px-5 py-3 border-b border-default">
            <span className="text-xs font-medium uppercase tracking-wider text-muted mr-1 select-none">
              FILTERS
            </span>

            {/* Severity Dropdown */}
            <div className="relative workflow-severity-dropdown">
              <button
                type="button"
                onClick={() => {
                  setSeverityDropdownOpen((v) => !v);
                  setPolicyDropdownOpen(false);
                }}
                className={`inline-flex items-center gap-2 rounded-lg border px-3.5 py-1.5 text-xs font-normal transition-colors shadow-sm ${hasPartialSeverity
                    ? "border-primary/40 bg-primary/10 text-primary font-medium"
                    : "border-default bg-surface text-muted hover:border-hover hover:text-text"
                  }`}
              >
                <span>
                  Severity:{" "}
                  <strong className="font-medium text-text">
                    {hasPartialSeverity ? `(${selectedSeverities.length})` : hasAllSeverities ? "All" : "(0)"}
                  </strong>
                </span>
                <ChevronDown className={`h-3.5 w-3.5 text-muted transition-transform ${severityDropdownOpen ? "rotate-180" : ""}`} />
              </button>

              {severityDropdownOpen && (
                <div className="absolute left-0 top-full mt-1.5 w-52 overflow-hidden rounded-xl border border-default bg-surface shadow-xl z-50 py-1">
                  <div className="flex items-center justify-between border-b border-default bg-surface px-3.5 py-2">
                    <button
                      type="button"
                      onClick={selectAllSeverities}
                      className="text-xs text-primary hover:underline font-medium"
                    >
                      Select All
                    </button>
                    <button
                      type="button"
                      onClick={clearAllSeverities}
                      className="text-xs text-muted hover:text-text"
                    >
                      Clear
                    </button>
                  </div>
                  {SEVERITY_ORDER.map((key) => (
                    <label
                      key={key}
                      className="group flex cursor-pointer items-center justify-between px-3.5 py-2 text-xs hover:bg-elevated text-left text-text transition-colors"
                    >
                      <span className="flex items-center gap-2">
                        <span className="h-2 w-2 rounded-full" style={{ backgroundColor: SEVERITY_FIGMA_COLORS[key]?.dot || "#999" }} />
                        <span className="capitalize">{formatApiText(key)}</span>
                        <span className="text-muted text-[11px]">({severityCounts[key] || 0})</span>
                      </span>
                      <input
                        type="checkbox"
                        checked={selectedSeverities.includes(key)}
                        onChange={() => toggleSeverity(key)}
                        className="h-3.5 w-3.5 rounded border-default bg-surface text-primary focus:ring-1 focus:ring-primary/30"
                      />
                    </label>
                  ))}
                </div>
              )}
            </div>

            {/* Policy Dropdown */}
            <div className="relative workflow-policy-dropdown">
              <button
                type="button"
                onClick={() => {
                  setPolicyDropdownOpen((v) => !v);
                  setSeverityDropdownOpen(false);
                }}
                className={`inline-flex items-center gap-2 rounded-lg border px-3.5 py-1.5 text-xs font-normal transition-colors shadow-sm ${hasPartialPolicies
                    ? "border-primary/40 bg-primary/10 text-primary font-medium"
                    : "border-default bg-surface text-muted hover:border-hover hover:text-text"
                  }`}
              >
                <span>
                  Policy:{" "}
                  <strong className="font-medium text-text">
                    {hasPartialPolicies ? `(${selectedPolicies.length})` : hasAllPolicies ? "All" : "(0)"}
                  </strong>
                </span>
                <ChevronDown className={`h-3.5 w-3.5 text-muted transition-transform ${policyDropdownOpen ? "rotate-180" : ""}`} />
              </button>

              {policyDropdownOpen && (
                <div className="absolute left-0 top-full mt-1.5 w-64 max-h-64 overflow-auto rounded-xl border border-default bg-surface shadow-xl z-50 py-1">
                  <div className="flex items-center justify-between border-b border-default bg-surface px-3.5 py-2">
                    <button
                      type="button"
                      onClick={selectAllPolicies}
                      className="text-xs text-primary hover:underline font-medium"
                    >
                      Select All
                    </button>
                    <button
                      type="button"
                      onClick={clearAllPolicies}
                      className="text-xs text-muted hover:text-text"
                    >
                      Clear
                    </button>
                  </div>
                  {policyOptions.map((policy) => (
                    <label
                      key={policy}
                      className="group flex cursor-pointer items-center justify-between px-3.5 py-2 text-xs hover:bg-elevated text-left text-text transition-colors"
                    >
                      <span className="truncate">{policy}</span>
                      <input
                        type="checkbox"
                        checked={(selectedPolicies ?? policyOptions).includes(policy)}
                        onChange={() => togglePolicy(policy)}
                        className="h-3.5 w-3.5 rounded border-default bg-surface text-primary focus:ring-1 focus:ring-primary/30 shrink-0 ml-2"
                      />
                    </label>
                  ))}
                </div>
              )}
            </div>

            {hasActiveFilters && (
              <button
                type="button"
                onClick={clearFilters}
                className="inline-flex items-center gap-1 rounded-lg border border-default px-2.5 py-1.5 text-xs text-muted hover:bg-elevated hover:text-text transition-colors"
              >
                <X className="h-3.5 w-3.5" />
                <span>Clear</span>
              </button>
            )}
          </div>

          <div
            className="overflow-x-auto scrollbar-hide-lg"
            ref={tableRef}
          >
            <table className="w-full min-w-[1120px] table-fixed">
              <colgroup>
                <col style={{ width: "14%" }} />
                <col style={{ width: "10%" }} />
                <col style={{ width: "18%" }} />
                <col style={{ width: "22%" }} />
                <col style={{ width: "16%" }} />
                <col style={{ width: "8%" }} />
                <col style={{ width: "12%" }} />
              </colgroup>
              <thead className="border-b border-default figma-table-head bg-[var(--table-head-bg)]">
                <tr>
                  <th className="px-6 py-3.5 text-center text-xs font-semibold text-text">Violation ID</th>
                  <th className="px-4 py-3.5 text-center text-xs font-semibold text-text">Severity</th>
                  <th className="px-4 py-3.5 text-center text-xs font-semibold text-text">Rule</th>
                  <th className="px-4 py-3.5 text-center text-xs font-semibold text-text">Description</th>
                  <th className="px-6 py-3.5 text-center text-xs font-semibold text-text">File</th>
                  <th className="px-4 py-3.5 text-center text-xs font-semibold text-text">Line</th>
                  <th className="px-6 py-3.5 text-center text-xs font-semibold text-text">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-default">
                {pagedTableRows.length > 0 ? (
                  pagedTableRows.map((row) => (
                    <tr
                      key={row.id}
                      className="group transition-colors hover:bg-elevated/40 border-b border-default"
                    >
                      <td className="px-6 py-3.5 align-middle text-left">
                        <span className="block font-mono text-xs font-bold text-[var(--text)] truncate text-left" title={row.policy_code}>
                          {row.policy_code}
                        </span>
                      </td>
                      <td className="px-4 py-3.5 align-middle text-left">
                        <TableSeverityBadge severity={row.severity} />
                      </td>
                      <td className="px-4 py-3.5 align-middle text-left">
                        <span className="block text-xs uppercase text-[var(--text)] font-semibold truncate text-left" title={row.policy_name}>
                          {row.policy_name}
                        </span>
                      </td>
                      <td className="px-4 py-3.5 align-middle text-left">
                        <span className="block break-words line-clamp-2 text-xs font-medium leading-relaxed text-[var(--text)] text-left" title={row.description}>
                          {row.description}
                        </span>
                      </td>
                      <td className="px-6 py-3.5 align-middle text-left">
                        <span className="block font-mono text-xs font-bold text-[var(--text)] truncate text-left" title={row.file_name}>
                          {row.file_name?.split("/").pop() || row.file_name?.split("\\").pop() || "Unknown"}
                        </span>
                      </td>
                      <td className="px-4 py-3.5 align-middle text-left">
                        <span className="block font-mono text-xs font-semibold text-[var(--text)] text-left">
                          {row.line_no}
                        </span>
                      </td>
                      <td className="px-6 py-3.5 align-middle text-left">
                        {row.remediation ? (
                          <a
                            href={row.remediation}
                            target="_blank"
                            rel="noopener noreferrer"
                            title="View details"
                            aria-label="View details"
                            className="inline-flex items-center gap-1 text-xs font-medium text-text hover:text-primary transition-colors whitespace-nowrap"
                          >
                            <span>Expand</span>
                            <ChevronRight className="h-3.5 w-3.5" />
                          </a>
                        ) : (
                          <span
                            className="inline-flex items-center gap-1 text-xs font-medium text-muted opacity-45 cursor-not-allowed whitespace-nowrap"
                            aria-label="No details"
                          >
                            <span>Expand</span>
                            <ChevronRight className="h-3.5 w-3.5" />
                          </span>
                        )}
                      </td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan="7" className="px-3 py-12 text-left text-muted">
                      <div className="flex flex-col items-center gap-2">
                        <FileText className="w-8 h-8 text-muted/50" />
                        <p className="text-sm">No findings match your filter criteria</p>
                      </div>
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>

          {tableRows.length > 0 && (
            <TablePagination
              currentPage={safePage}
              totalPages={totalPages}
              totalItems={tableRows.length}
              pageSize={pageSize}
              setPageSize={setPageSize}
              setCurrentPage={setCurrentPage}
              pageSizeOptions={PAGE_SIZE_OPTIONS}
            />
          )}
        </section>
      </main>
    </div>
  );
};

const getSeverityColor = (severity) => {
  const colors = {
    critical: "#EF4444",
    high: "#F97316",
    medium: "#3B82F6",
    low: "#8B5CF6",
  };
  return colors[severity] || "#94A3B8";
};

const getPolicyColor = (policyCode) => {
  const colors = [
    "#06B6D4",
    "#8B5CF6",
    "#EC4899",
    "#F97316",
    "#22C55E",
    "#EAB308",
  ];
  const index = policyCode
    ? policyCode.split("").reduce((a, c) => a + c.charCodeAt(0), 0)
    : 0;
  return colors[index % colors.length];
};

const getScoreColor = (score) => {
  if (score >= 90) return "#22C55E";
  if (score >= 70) return "#F59E0B";
  return "#EF4444";
};

const toFiniteNumber = (value, fallback = 0) => {
  const number = Number(value);
  return Number.isFinite(number) ? number : fallback;
};

const trimPath = (path = "") => {
  const parts = path.split("/");
  return parts.length > 3 ? parts.slice(-3).join("/") : path;
};

const formatDate = (rawDate) => {
  if (!rawDate) return "N/A";
  const parsed = new Date(rawDate);
  return Number.isNaN(parsed.getTime()) ? "N/A" : parsed.toLocaleDateString();
};

const formatDateTime = (rawDate) => {
  if (!rawDate) return "N/A";
  const parsed = new Date(rawDate);
  if (Number.isNaN(parsed.getTime())) return "N/A";

  return parsed.toLocaleString([], {
    year: "numeric",
    month: "long",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
};

const cleanDescription = (description = "") => {
  return description.split("| Remediation:")[0]?.trim() || description;
};

const resolveRemediation = (policy = {}) => {
  if (policy.remediation && policy.remediation !== "N/A") {
    return policy.remediation;
  }
  const matches = policy.description?.match(/(https?:\/\/[^\s|]+)/);
  return matches ? matches[0] : "";
};

const getSeverityBadgeStyle = (severity) => {
  return getSharedSeverityBadgeStyle(severity, { variant: "figma" });
};

const getSeverityIcon = (severity) => {
  return getSharedSeverityIcon(severity);
};

const getSeverityColorForUI = (severity) => {
  return getSeverityColorToken(severity);
};

const renderSeverityBadge = (severity) => {
  return (
    <span
      className="inline-flex min-w-[70px] items-center justify-center rounded-[5px] px-2.5 py-1 text-[11px] font-bold uppercase tracking-wider"
      style={getSeverityBadgeStyle(severity)}
    >
      {formatApiText(severity)}
    </span>
  );
};

export default Workflow;