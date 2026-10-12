import React, { useEffect, useMemo, useRef, useState } from "react";
import { Search, X, Eye, EyeOff, Key, ChevronLeft, ChevronRight, ChevronDown, Check, FileText, Filter } from "lucide-react";
import FindingDetailsSidebar from "./FindingDetailsSidebar";
import workflowStyles from "../workflow/Workflow.module.css";
import TablePagination from "../shared/TablePagination";
import {
  getSeverityBadgeStyle as getSharedSeverityBadgeStyle,
  getSeverityIcon as getSharedSeverityIcon,
  getSeverityColorToken,
  SEVERITY_FIGMA_COLORS,
  normalizeSeverity,
  TableSeverityBadge,
} from "../shared/severityVisuals";
import { useInteractiveTable } from "../shared/useInteractiveTable";

const PAGE_SIZE_OPTIONS = [10, 25, 50, 100];
const SEVERITY_ORDER = ["critical", "high", "medium", "low"];

const getPaginationPages = (current, total) => {
  if (total <= 7) return Array.from({ length: total }, (_, i) => i + 1);
  if (current <= 4) return [1, 2, 3, 4, 5, "…", total];
  if (current >= total - 3) return [1, "…", total - 4, total - 3, total - 2, total - 1, total];
  return [1, "…", current - 1, current, current + 1, "…", total];
};

const FindingsList = ({ findings }) => {
  const [searchTerm, setSearchTerm] = useState("");
  const [selectedSeverities, setSelectedSeverities] = useState(SEVERITY_ORDER);
  const [selectedCategories, setSelectedCategories] = useState(null); // null means all
  const [selectedPatternTypes, setSelectedPatternTypes] = useState(null); // null means all
  const [currentPage, setCurrentPage] = useState(1);
  const [pageSize, setPageSize] = useState(25);
  const [visibleCredentials, setVisibleCredentials] = useState({});
  const [selectedFinding, setSelectedFinding] = useState(null);
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [severityDropdownOpen, setSeverityDropdownOpen] = useState(false);
  const [categoryDropdownOpen, setCategoryDropdownOpen] = useState(false);
  const [patternDropdownOpen, setPatternDropdownOpen] = useState(false);
  const tableRef = useRef(null);

  // Extract all unique values for filters
  const categories = useMemo(() => {
    const cats = new Set();
    findings?.forEach(finding => {
      if (finding.category) {
        cats.add(finding.category);
      }
    });
    return Array.from(cats).sort();
  }, [findings]);

  const severityCounts = useMemo(() => {
    const counts = { critical: 0, high: 0, medium: 0, low: 0 };
    findings?.forEach((finding) => {
      const tone = String(finding?.severity || "").toLowerCase();
      if (counts[tone] !== undefined) {
        counts[tone] += 1;
      }
    });
    return counts;
  }, [findings]);

  const patternTypes = useMemo(() => {
    const patterns = new Set();
    findings?.forEach(finding => {
      if (finding.pattern_type) {
        patterns.add(finding.pattern_type);
      }
    });
    return Array.from(patterns).sort();
  }, [findings]);

  // Multi-select helpers
  const toggleSeverity = (sev) => {
    setSelectedSeverities(prev =>
      prev.includes(sev) ? prev.filter(s => s !== sev) : [...prev, sev]
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

  const toggleCategory = (cat) => {
    const current = selectedCategories ?? categories;
    const next = current.includes(cat) ? current.filter(c => c !== cat) : [...current, cat];
    setSelectedCategories(next.length === categories.length ? null : next);
    setCurrentPage(1);
  };
  const selectAllCategories = () => {
    setSelectedCategories(null);
    setCurrentPage(1);
  };
  const clearAllCategories = () => {
    setSelectedCategories([]);
    setCurrentPage(1);
  };

  const togglePatternType = (pat) => {
    const current = selectedPatternTypes ?? patternTypes;
    const next = current.includes(pat) ? current.filter(p => p !== pat) : [...current, pat];
    setSelectedPatternTypes(next.length === patternTypes.length ? null : next);
    setCurrentPage(1);
  };
  const selectAllPatternTypes = () => {
    setSelectedPatternTypes(null);
    setCurrentPage(1);
  };
  const clearAllPatternTypes = () => {
    setSelectedPatternTypes([]);
    setCurrentPage(1);
  };

  // Filter findings based on search and filters
  const filteredFindings = useMemo(() => {
    const term = searchTerm.toLowerCase();
    const activeCats = selectedCategories ?? categories;
    const activePats = selectedPatternTypes ?? patternTypes;

    return (
      findings?.filter((finding) => {
        const fileName = finding.file_name || "";

        const matchesSearch =
          searchTerm === "" ||
          fileName.toLowerCase().includes(term) ||
          finding.pattern_type?.toLowerCase().includes(term) ||
          finding.category?.toLowerCase().includes(term);

        const matchesCategory =
          selectedCategories === null
            ? true
            : activeCats.some(c => c.toLowerCase() === (finding.category || "").toLowerCase());

        const matchesSeverity =
          selectedSeverities.includes(String(finding.severity || "").toLowerCase());

        const matchesPattern =
          selectedPatternTypes === null
            ? true
            : activePats.some(p => p.toLowerCase() === (finding.pattern_type || "").toLowerCase());

        return matchesSearch && matchesCategory && matchesSeverity && matchesPattern;
      }) || []
    );
  }, [findings, searchTerm, selectedCategories, categories, selectedSeverities, selectedPatternTypes, patternTypes]);

  const toggleCredential = (credentialId) => {
    setVisibleCredentials(prev => ({
      ...prev,
      [credentialId]: !prev[credentialId]
    }));
  };

  const openFindingDetails = (finding) => {
    setSelectedFinding(finding);
    setSidebarOpen(true);
  };

  const closeFindingDetails = () => {
    setSidebarOpen(false);
    setSelectedFinding(null);
  };

  const clearFilters = () => {
    setSearchTerm("");
    setSelectedCategories(null);
    setSelectedSeverities(SEVERITY_ORDER);
    setSelectedPatternTypes(null);
  };

  const hasAllSeverities = selectedSeverities.length === SEVERITY_ORDER.length;
  const hasPartialSeverity = selectedSeverities.length > 0 && selectedSeverities.length < SEVERITY_ORDER.length;

  const hasAllCategories = selectedCategories === null || selectedCategories.length === categories.length;
  const hasPartialCategories = selectedCategories !== null && selectedCategories.length > 0 && selectedCategories.length < categories.length;

  const hasAllPatternTypes = selectedPatternTypes === null || selectedPatternTypes.length === patternTypes.length;
  const hasPartialPatternTypes = selectedPatternTypes !== null && selectedPatternTypes.length > 0 && selectedPatternTypes.length < patternTypes.length;

  const hasActiveFilters =
    searchTerm !== "" ||
    (selectedCategories !== null && selectedCategories.length < categories.length) ||
    selectedSeverities.length < SEVERITY_ORDER.length ||
    (selectedPatternTypes !== null && selectedPatternTypes.length < patternTypes.length);

  useEffect(() => {
    const handleClickOutside = (event) => {
      if (
        !event.target.closest(".secret-severity-dropdown") &&
        !event.target.closest(".secret-category-dropdown") &&
        !event.target.closest(".secret-pattern-dropdown")
      ) {
        setSeverityDropdownOpen(false);
        setCategoryDropdownOpen(false);
        setPatternDropdownOpen(false);
      }
    };

    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);

  const totalPages = Math.max(1, Math.ceil(filteredFindings.length / pageSize));
  const safePage = Math.min(currentPage, totalPages);
  const pageStart = (safePage - 1) * pageSize;
  const pageEnd = Math.min(pageStart + pageSize, filteredFindings.length);
  const pagedFindings = filteredFindings.slice(pageStart, pageEnd);

  useInteractiveTable({
    containerRef: tableRef,
    storageKey: "scanops-secret-findings-table",
    minWidth: 88,
    deps: [
      pagedFindings.length,
      currentPage,
      pageSize,
      searchTerm,
      selectedCategories,
      selectedSeverities,
      selectedPatternTypes,
    ],
  });

  const goToPage = (page) => {
    const clamped = Math.max(1, Math.min(page, totalPages));
    setCurrentPage(clamped);
    tableRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
  };

  const totalFilteredFiles = new Set(filteredFindings.map((f) => f.file_name)).size;
  const totalFilteredIssues = filteredFindings.length;

  // Get summary counts by pattern type
  const patternSummary = useMemo(() => {
    const summary = {};
    findings?.forEach(finding => {
      const pattern = finding.pattern_type;
      if (pattern) {
        summary[pattern] = (summary[pattern] || 0) + 1;
      }
    });
    return summary;
  }, [findings]);

  const getPatternChipStyle = (index) => {
    const chips = [
      {
        backgroundColor: "rgba(249, 115, 22, 0.1)",
        border: "1px solid rgba(249, 115, 22, 0.3)",
        color: "#fb923c",
      },
      {
        backgroundColor: "rgba(236, 72, 153, 0.1)",
        border: "1px solid rgba(236, 72, 153, 0.3)",
        color: "#f472b6",
      },
      {
        backgroundColor: "rgba(139, 92, 246, 0.1)",
        border: "1px solid rgba(139, 92, 246, 0.3)",
        color: "#a78bfa",
      },
      {
        backgroundColor: "rgba(34, 197, 94, 0.1)",
        border: "1px solid rgba(34, 197, 94, 0.3)",
        color: "#4ade80",
      },
    ];
    return chips[index % chips.length];
  };

  const formatSeverityLabel = (value) => {
    const text = String(value || "").toLowerCase();
    if (!text) return "Unknown";
    return text.charAt(0).toUpperCase() + text.slice(1);
  };

  const formatPatternLabel = (pattern) => {
    if (!pattern) return "UNKNOWN";
    const lastToken = pattern.split("/").pop() || pattern;
    return lastToken.replace(/[_-]+/g, " ").toUpperCase();
  };

  const getSeverityBadgeStyle = (severity) => {
    return getSharedSeverityBadgeStyle(severity, { blur: true });
  };

  const getRedactedPreview = (value) => {
    if (!value) return "N/A";
    return value.length > 20 ? `${value.substring(0, 20)}...` : value;
  };

  const getSeverityIcon = (severity) => {
    return getSharedSeverityIcon(severity);
  };

  const getSeverityColorForUI = (severity) => {
    return getSeverityColorToken(severity);
  };

  return (
    <div className="rounded-lg border border-default bg-surface shadow-sm overflow-hidden">
      {/* Header */}
      <div className="px-6 pt-6 pb-4">
        <div className="mb-3 flex flex-wrap items-start justify-between gap-3">
          <div>
            <h3 style={{ margin: 0, fontFamily: "var(--font-ui)", fontSize: "11px", fontWeight: 700, letterSpacing: "0.08em", textTransform: "uppercase", color: "var(--muted)" }}>
              Secret Scanner Findings
            </h3>
            <p className="text-sm mt-1" style={{ color: "var(--muted)" }}>
              {totalFilteredIssues} detection{totalFilteredIssues !== 1 ? "s" : ""} found • {totalFilteredFiles} file{totalFilteredFiles !== 1 ? "s" : ""}
            </p>
          </div>

          <label className={workflowStyles.searchBox} style={{ width: "min(100%, 384px)" }}>
            <Search size={16} />
            <input
              type="text"
              placeholder="Search by file, pattern..."
              value={searchTerm}
              onChange={(e) => {
                setSearchTerm(e.target.value);
                setCurrentPage(1);
              }}
            />
          </label>
        </div>

        {/* Pattern Summary Cards */}
        {Object.keys(patternSummary).length > 0 && (
          <div className="mb-4 flex flex-wrap items-center gap-2">
            {Object.entries(patternSummary)
              .sort((a, b) => b[1] - a[1])
              .slice(0, 5)
              .map(([pattern, count], index) => {
                const chipStyle = getPatternChipStyle(index);
                return (
                  <div
                    key={pattern}
                    className="inline-flex h-[26px] items-center gap-1.5 rounded-full px-3"
                    style={{
                      backgroundColor: chipStyle.backgroundColor,
                      border: chipStyle.border,
                    }}
                  >
                    <span className="text-[10px] font-semibold leading-4" style={{ color: chipStyle.color }}>
                      {formatPatternLabel(pattern)}
                    </span>
                    <span
                      className="inline-flex h-4 min-w-4 items-center justify-center rounded-full px-1.5 text-[10px] font-semibold leading-4"
                      style={{
                        backgroundColor: "var(--elevated-surface)",
                        color: "var(--muted)",
                      }}
                    >
                      {count}
                    </span>
                  </div>
                );
              })}
          </div>
        )}

        {/* Filters */}
        <div className="flex flex-wrap items-center gap-3 pt-1">
          <span className="text-xs font-medium uppercase tracking-wider text-muted mr-1 select-none">
            FILTERS
          </span>

          {/* Severity Dropdown */}
          <div className="relative secret-severity-dropdown">
            <button
              type="button"
              onClick={() => {
                setSeverityDropdownOpen((v) => !v);
                setCategoryDropdownOpen(false);
                setPatternDropdownOpen(false);
              }}
              className={`inline-flex items-center gap-2 rounded-lg border px-3.5 py-1.5 text-xs font-normal transition-colors shadow-sm ${
                hasPartialSeverity
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
              <div className="absolute left-0 top-full mt-1.5 w-52 overflow-hidden rounded-lg border border-default bg-surface shadow-xl z-50 py-1">
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
                {SEVERITY_ORDER.map((sev) => (
                  <label
                    key={sev}
                    className="group flex cursor-pointer items-center justify-between px-3.5 py-2 text-xs hover:bg-elevated text-left text-text transition-colors"
                  >
                    <span className="flex items-center gap-2">
                      <span className="h-2 w-2 rounded-full" style={{ backgroundColor: SEVERITY_FIGMA_COLORS[sev]?.dot || "#999" }} />
                      <span className="capitalize">{sev}</span>
                      <span className="text-muted text-[11px]">({severityCounts[sev] || 0})</span>
                    </span>
                    <input
                      type="checkbox"
                      checked={selectedSeverities.includes(sev)}
                      onChange={() => toggleSeverity(sev)}
                      className="h-3.5 w-3.5 rounded border-default bg-surface text-primary focus:ring-1 focus:ring-primary/30"
                    />
                  </label>
                ))}
              </div>
            )}
          </div>

          {/* Category Dropdown */}
          <div className="relative secret-category-dropdown">
            <button
              type="button"
              onClick={() => {
                setCategoryDropdownOpen((v) => !v);
                setSeverityDropdownOpen(false);
                setPatternDropdownOpen(false);
              }}
              className={`inline-flex items-center gap-2 rounded-lg border px-3.5 py-1.5 text-xs font-normal transition-colors shadow-sm ${
                hasPartialCategories
                  ? "border-primary/40 bg-primary/10 text-primary font-medium"
                  : "border-default bg-surface text-muted hover:border-hover hover:text-text"
              }`}
            >
              <span>
                Category:{" "}
                <strong className="font-medium text-text">
                  {hasPartialCategories ? `(${selectedCategories.length})` : hasAllCategories ? "All" : "(0)"}
                </strong>
              </span>
              <ChevronDown className={`h-3.5 w-3.5 text-muted transition-transform ${categoryDropdownOpen ? "rotate-180" : ""}`} />
            </button>

            {categoryDropdownOpen && (
              <div className="absolute left-0 top-full mt-1.5 w-64 max-h-64 overflow-auto rounded-lg border border-default bg-surface shadow-xl z-50 py-1">
                <div className="flex items-center justify-between border-b border-default bg-surface px-3.5 py-2">
                  <button
                    type="button"
                    onClick={selectAllCategories}
                    className="text-xs text-primary hover:underline font-medium"
                  >
                    Select All
                  </button>
                  <button
                    type="button"
                    onClick={clearAllCategories}
                    className="text-xs text-muted hover:text-text"
                  >
                    Clear
                  </button>
                </div>
                {categories.map((cat) => (
                  <label
                    key={cat}
                    className="group flex cursor-pointer items-center justify-between px-3.5 py-2 text-xs hover:bg-elevated text-left text-text transition-colors"
                  >
                    <span className="truncate">{cat}</span>
                    <input
                      type="checkbox"
                      checked={(selectedCategories ?? categories).includes(cat)}
                      onChange={() => toggleCategory(cat)}
                      className="h-3.5 w-3.5 rounded border-default bg-surface text-primary focus:ring-1 focus:ring-primary/30 shrink-0 ml-2"
                    />
                  </label>
                ))}
              </div>
            )}
          </div>

          {/* Pattern Type Dropdown */}
          <div className="relative secret-pattern-dropdown">
            <button
              type="button"
              onClick={() => {
                setPatternDropdownOpen((v) => !v);
                setSeverityDropdownOpen(false);
                setCategoryDropdownOpen(false);
              }}
              className={`inline-flex items-center gap-2 rounded-lg border px-3.5 py-1.5 text-xs font-normal transition-colors shadow-sm ${
                hasPartialPatternTypes
                  ? "border-primary/40 bg-primary/10 text-primary font-medium"
                  : "border-default bg-surface text-muted hover:border-hover hover:text-text"
              }`}
            >
              <span>
                Pattern:{" "}
                <strong className="font-medium text-text">
                  {hasPartialPatternTypes ? `(${selectedPatternTypes.length})` : hasAllPatternTypes ? "All" : "(0)"}
                </strong>
              </span>
              <ChevronDown className={`h-3.5 w-3.5 text-muted transition-transform ${patternDropdownOpen ? "rotate-180" : ""}`} />
            </button>

            {patternDropdownOpen && (
              <div className="absolute left-0 top-full mt-1.5 w-64 max-h-64 overflow-auto rounded-lg border border-default bg-surface shadow-xl z-50 py-1">
                <div className="flex items-center justify-between border-b border-default bg-surface px-3.5 py-2">
                  <button
                    type="button"
                    onClick={selectAllPatternTypes}
                    className="text-xs text-primary hover:underline font-medium"
                  >
                    Select All
                  </button>
                  <button
                    type="button"
                    onClick={clearAllPatternTypes}
                    className="text-xs text-muted hover:text-text"
                  >
                    Clear
                  </button>
                </div>
                {patternTypes.map((pattern) => (
                  <label
                    key={pattern}
                    className="group flex cursor-pointer items-center justify-between px-3.5 py-2 text-xs hover:bg-elevated text-left text-text transition-colors"
                  >
                    <span className="truncate">{pattern}</span>
                    <input
                      type="checkbox"
                      checked={(selectedPatternTypes ?? patternTypes).includes(pattern)}
                      onChange={() => togglePatternType(pattern)}
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
      </div>

      {/* Findings Table */}
      <div
        ref={tableRef}
        className="overflow-x-auto"
        style={{
          scrollbarWidth: 'none',
          msOverflowStyle: 'none',
        }}
      >
        <table className="w-full min-w-[1040px] table-fixed">
          <colgroup>
            <col style={{ width: "24%" }} />
            <col style={{ width: "12%" }} />
            <col style={{ width: "20%" }} />
            <col style={{ width: "24%" }} />
            <col style={{ width: "8%" }} />
            <col style={{ width: "12%" }} />
          </colgroup>
          <thead className="border-b border-default figma-table-head bg-[var(--table-head-bg)]">
            <tr>
              <th className="px-6 py-3.5 text-center text-xs font-semibold text-text">Violation ID</th>
              <th className="px-4 py-3.5 text-center text-xs font-semibold text-text">Severity</th>
              <th className="px-4 py-3.5 text-center text-xs font-semibold text-text">Category</th>
              <th className="px-6 py-3.5 text-center text-xs font-semibold text-text">File</th>
              <th className="px-4 py-3.5 text-center text-xs font-semibold text-text">Line</th>
              <th className="px-6 py-3.5 text-center text-xs font-semibold text-text">Action</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-default">
            {pagedFindings.length > 0 ? pagedFindings.map((finding, idx) => {
              const credentialId = finding.id || `${finding.file_name}-${finding.line_no}-${idx}`;

              return (
                <tr
                  key={credentialId}
                  className="group transition-colors hover:bg-elevated/40 border-b border-default"
                >
                  <td className="px-6 py-3.5 align-middle max-w-0 text-left">
                    <span
                      className="block truncate font-mono text-xs font-bold text-[var(--text)] text-left"
                      title={finding.pattern_type || "N/A"}
                    >
                      {finding.pattern_type || "N/A"}
                    </span>
                  </td>
                  <td className="px-4 py-3.5 align-middle text-left">
                    <TableSeverityBadge severity={finding.severity} />
                  </td>
                  <td className="px-4 py-3.5 align-middle text-left">
                    <span className="block text-xs uppercase text-[var(--text)] font-semibold truncate text-left" title={finding.category}>
                      {finding.category || "N/A"}
                    </span>
                  </td>
                  <td className="px-6 py-3.5 align-middle text-left">
                    <span className="block font-mono text-xs font-bold text-[var(--text)] truncate text-left" title={finding.file_name}>
                      {finding.file_name?.split("/").pop() || finding.file_name?.split("\\").pop() || "Unknown"}
                    </span>
                  </td>
                  <td className="px-4 py-3.5 align-middle text-left">
                    <span className="block font-mono text-xs font-semibold text-[var(--text)] text-left">
                      {finding.line_no || "N/A"}
                    </span>
                  </td>
                  <td className="px-6 py-3.5 align-middle text-left">
                    <button
                      type="button"
                      onClick={() => openFindingDetails(finding)}
                      aria-label="View details"
                      title="Expand finding details"
                      className="inline-flex items-center gap-1 text-xs font-medium text-text hover:text-primary transition-colors whitespace-nowrap"
                    >
                      <span>Expand</span>
                      <ChevronRight className="h-3.5 w-3.5" />
                    </button>
                  </td>
                </tr>
              );
            }) : (
              <tr>
                <td colSpan="6" className="px-3 py-12 text-left text-muted">
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

      {totalFilteredIssues > 0 && (
        <TablePagination
          currentPage={safePage}
          totalPages={totalPages}
          totalItems={filteredFindings.length}
          pageSize={pageSize}
          setPageSize={setPageSize}
          setCurrentPage={setCurrentPage}
          pageSizeOptions={PAGE_SIZE_OPTIONS}
        />
      )}

      {/* Finding Details Sidebar */}
      <FindingDetailsSidebar
        finding={selectedFinding}
        isOpen={sidebarOpen}
        onClose={closeFindingDetails}
      />
    </div>
  );
};

export default FindingsList;