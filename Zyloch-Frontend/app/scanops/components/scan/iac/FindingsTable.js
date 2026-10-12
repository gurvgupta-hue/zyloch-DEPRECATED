import React, { useState, useEffect, useRef } from "react";
import { ChevronRight } from "lucide-react";
import SmartTruncate from "@/components/ui/SmartTruncate";
import TechIcon from "@/components/common/TechIcon";
import PolicyDetailsSidebar from "./PolicyDetailsSidebar";
import {
  getProviderBadgeStyle,
} from "./utils/styles";
import {
  getSeverityBadgeStyle as getSharedSeverityBadgeStyle,
  getSeverityIcon as getSharedSeverityIcon,
  SEVERITY_FIGMA_COLORS,
  normalizeSeverity,
  TableSeverityBadge,
} from "../shared/severityVisuals";
import { useInteractiveTable } from "../shared/useInteractiveTable";
import TablePagination from "../shared/TablePagination";

const getTypeMeta = (type) => {
  const normalizedType = String(type || "").toLowerCase();

  if (normalizedType === "docker") {
    return { iconName: "docker", label: "Docker", color: "#2496ED" };
  }

  if (normalizedType === "kubernetes") {
    return { iconName: "kubernetes", label: "Kubernetes", color: "#326CE5" };
  }

  if (normalizedType === "terraform") {
    return { iconName: "terraform", label: "Terraform", color: "#7B42F6" };
  }

  if (normalizedType === "bicep") {
    return { iconName: "bicep", label: "Bicep", color: "#0078D4" };
  }

  if (normalizedType === "arm") {
    return { iconName: "arm", label: "ARM", color: "#FF6B35" };
  }

  if (normalizedType === "ansible") {
    return { iconName: "ansible", label: "Ansible", color: "#EE0000" };
  }

  if (normalizedType === "cloudformation") {
    return { iconName: "aws", label: "CloudFormation", color: "#FF9900" };
  }

  return { iconName: "file", label: type || "Unknown", color: "currentColor" };
};

const getDisplayFileName = (filePath) => {
  if (!filePath) return "N/A";
  const normalized = String(filePath).replace(/\\/g, "/");
  const parts = normalized.split("/").filter(Boolean);
  const baseName = parts[parts.length - 1] || normalized;

  // Dockerfiles are almost always literally named "Dockerfile", so keep the
  // immediate parent folder (e.g. "backend/Dockerfile") to distinguish
  // between multiple Dockerfiles in the same repo instead of collapsing
  // them all down to the same bare "Dockerfile".
  if (baseName.toLowerCase() === "dockerfile" && parts.length > 1) {
    return `${parts[parts.length - 2]}/${baseName}`;
  }

  return baseName;
};

const getValidLineNumber = (lineNo) => {
  const parsed = Number(lineNo);
  return Number.isFinite(parsed) && parsed > 0 ? String(parsed) : null;
};

const getProviderMeta = (provider) => {
  const normalized = String(provider || "").toLowerCase();

  if (normalized === "aws") {
    return { iconName: "aws", label: "AWS", color: "#FF9900" };
  }

  if (normalized === "azure") {
    return { iconName: "azure", label: "Azure", color: "#0078D4" };
  }

  if (normalized === "gcp" || normalized === "google") {
    return { iconName: "gcp", label: "GCP", color: "#4285F4" };
  }

  return { iconName: null, label: provider || "Provider", color: "var(--text)" };
};

const ProviderIconBadge = ({ provider, className = "" }) => {
  const { iconName, label, color } = getProviderMeta(provider);

  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-[11px] font-medium capitalize ${className}`.trim()}
      title={label}
      aria-label={label}
    >
      {iconName && <TechIcon name={iconName} size={12} color={color} />}
      <span>{label}</span>
    </span>
  );
};

const getSeverityIcon = (severity) => {
  return getSharedSeverityIcon(severity);
};

const getSeverityBadgeStyle = (severity) => {
  return getSharedSeverityBadgeStyle(severity, { blur: true });
};

const formatSeverityLabel = (severity) => {
  const text = String(severity || "").toLowerCase();
  if (!text) return "Unknown";
  return text.charAt(0).toUpperCase() + text.slice(1);
};

const SeverityBadge = ({ severity }) => {
  return <TableSeverityBadge severity={severity} />;
};

const TypeIconBadge = ({ type, provider }) => {
  const normalizedType = String(type || "").toLowerCase();
  const normalizedProvider = String(provider || "").toLowerCase();

  const isTerraformAws = normalizedType === "terraform" && normalizedProvider === "aws";
  const isTerraformAzure = normalizedType === "terraform" && normalizedProvider === "azure";
  const isTerraformGcp = normalizedType === "terraform" && (normalizedProvider === "gcp" || normalizedProvider === "google");
  const isDual = isTerraformAws || isTerraformAzure || isTerraformGcp;

  if (isDual) {
    const cloudAccent = isTerraformAws ? "#FF9900" : isTerraformAzure ? "#0078D4" : "#4285F4";
    const cloudIconName = isTerraformAws ? "aws" : isTerraformAzure ? "azure" : "gcp";
    return (
      <span
        style={{
          display: "inline-flex",
          alignItems: "center",
          gap: "4px",
          height: "28px",
          padding: "0 6px",
          borderRadius: "8px",
          background: `linear-gradient(90deg, color-mix(in srgb, #7B42F6 12%, var(--surface)) 0%, color-mix(in srgb, ${cloudAccent} 12%, var(--surface)) 100%)`,
          border: `1px solid color-mix(in srgb, ${cloudAccent} 35%, var(--border))`,
          flexShrink: 0,
        }}
      >
        <span
          style={{
            width: "18px",
            height: "18px",
            display: "inline-flex",
            alignItems: "center",
            justifyContent: "center",
            borderRadius: "4px",
            background: "color-mix(in srgb, #7B42F6 14%, var(--surface))",
            border: "1px solid color-mix(in srgb, #7B42F6 30%, transparent)",
          }}
        >
          <TechIcon name="terraform" size={11} color="#7B42F6" />
        </span>
        <span
          style={{
            width: "1px",
            height: "12px",
            borderRadius: "1px",
            background: "color-mix(in srgb, var(--muted) 55%, transparent)",
          }}
        />
        <span
          style={{
            width: "18px",
            height: "18px",
            display: "inline-flex",
            alignItems: "center",
            justifyContent: "center",
            borderRadius: "4px",
            background: `color-mix(in srgb, ${cloudAccent} 14%, var(--surface))`,
            border: `1px solid color-mix(in srgb, ${cloudAccent} 30%, transparent)`,
          }}
        >
          <TechIcon name={cloudIconName} size={11} color={cloudAccent} />
        </span>
      </span>
    );
  }

  const { iconName, label, color } = getTypeMeta(type);
  return (
    <span
      style={{
        display: "inline-flex",
        alignItems: "center",
        justifyContent: "center",
        width: "28px",
        height: "28px",
        borderRadius: "8px",
        background: `color-mix(in srgb, ${color} 12%, var(--surface))`,
        border: `1px solid color-mix(in srgb, ${color} 25%, var(--border))`,
        flexShrink: 0,
      }}
      title={label}
      aria-label={label}
    >
      <TechIcon name={iconName} size={15} color={color} />
    </span>
  );
};

const PAGE_SIZE_OPTIONS = [10, 25, 50, 100];

const getPaginationPages = (current, total) => {
  if (total <= 7) return Array.from({ length: total }, (_, i) => i + 1);
  if (current <= 4) return [1, 2, 3, 4, 5, "…", total];
  if (current >= total - 3) return [1, "…", total - 4, total - 3, total - 2, total - 1, total];
  return [1, "…", current - 1, current, current + 1, "…", total];
};

const FindingsTable = ({
  findings,
  totalFindings,
  dockerCount,
  kubernetesCount,
  terraformCount,
  terraformAwsCount,
  terraformAzureCount,
  terraformGcpCount,
  bicepCount,
  armCount,
  ansibleCount,
  repositoryContext,
}) => {
  const [selectedFinding, setSelectedFinding] = useState(null);
  const [isSidebarOpen, setIsSidebarOpen] = useState(false);
  const [currentPage, setCurrentPage] = useState(1);
  const [pageSize, setPageSize] = useState(25);
  const tableRef = useRef(null);

  // Reset to page 1 when findings list changes (filter applied)
  useEffect(() => {
    setCurrentPage(1);
  }, [findings]);

  const totalPages = Math.max(1, Math.ceil(findings.length / pageSize));
  const safePage = Math.min(currentPage, totalPages);
  const pageStart = (safePage - 1) * pageSize;
  const pageEnd = Math.min(pageStart + pageSize, findings.length);
  const pagedFindings = findings.slice(pageStart, pageEnd);

  useInteractiveTable({
    containerRef: tableRef,
    storageKey: "scanops-iac-findings-table",
    minWidth: 84,
    deps: [pagedFindings.length, safePage, pageSize],
  });

  const goToPage = (page) => {
    const clamped = Math.max(1, Math.min(page, totalPages));
    setCurrentPage(clamped);
    tableRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
  };

  const handleFindingClick = (finding) => {
    setSelectedFinding(finding);
    setIsSidebarOpen(true);
  };

  const handleCloseSidebar = () => {
    setIsSidebarOpen(false);
    setTimeout(() => setSelectedFinding(null), 300);
  };

  useEffect(() => {
    document.body.style.overflow = isSidebarOpen ? "hidden" : "auto";
    return () => {
      document.body.style.overflow = "auto";
    };
  }, [isSidebarOpen]);

  return (
    <>
      <PolicyDetailsSidebar
        finding={selectedFinding}
        repositoryContext={repositoryContext}
        isOpen={isSidebarOpen}
        onClose={handleCloseSidebar}
      />

      <div
        ref={tableRef}
        className={`rounded-lg border border-default bg-surface shadow-sm overflow-hidden transition-opacity duration-300 ${isSidebarOpen ? "pointer-events-none opacity-40" : "pointer-events-auto opacity-100"}`}
      >
        <div className="md:hidden divide-y divide-default">
          {pagedFindings.length > 0 ? (
            pagedFindings.map((finding, index) => {
              const rowKey = `${finding.policyCode || "policy"}-${finding.file || "file"}-${finding.lineNo || "line"}-${index}`;

              return (
                <article key={rowKey} className="m-3 rounded-xl border border-default bg-elevated/20 p-3.5">
                  <div className="flex items-start justify-between gap-2">
                    <div className="min-w-0">
                      <p className="text-xs font-mono text-muted truncate">{finding.policyCode || "N/A"}</p>
                      <h3 className="mt-1 text-sm font-semibold text-text line-clamp-2">{finding.title || "Security finding"}</h3>
                    </div>
                    <button
                      type="button"
                      onClick={(event) => {
                        event.stopPropagation();
                        handleFindingClick(finding);
                      }}
                      title="View details"
                      aria-label="View details"
                      className="inline-flex h-8 w-8 shrink-0 items-center justify-center rounded-md border border-default bg-elevated text-muted transition-colors-fast hover:border-hover hover:bg-surface hover:text-text"
                    >
                      <TechIcon name="eye" size={16} />
                    </button>
                  </div>

                  <div className="mt-2.5 flex flex-wrap items-center gap-2">
                    <SeverityBadge severity={finding.severity} />
                    <TypeIconBadge type={finding.type} provider={finding.provider} />
                    {finding.provider && finding.provider !== finding.type && (
                      <ProviderIconBadge
                        provider={finding.provider}
                        className={getProviderBadgeStyle(finding.provider)}
                      />
                    )}
                  </div>

                  <div className="mt-2 text-xs text-muted space-y-1">
                    <p className="truncate"><span className="text-muted/80">Category:</span> {finding.category || "Uncategorized"}</p>
                    <p className="truncate"><span className="text-muted/80">File:</span> {getDisplayFileName(finding.file)}{getValidLineNumber(finding.lineNo) ? ` · Line ${getValidLineNumber(finding.lineNo)}` : ""}</p>
                  </div>
                </article>
              );
            })
          ) : (
            <div className="px-4 py-10 text-center text-muted">
              <div className="flex flex-col items-center gap-2">
                <TechIcon name="file" size={28} color="var(--muted)" opacity={0.5} />
                <p className="text-sm">No findings match your filter criteria</p>
              </div>
            </div>
          )}
        </div>

        <div className="hidden md:block overflow-x-auto">
          <table className="w-full min-w-[900px]">
            <thead className="border-b border-default figma-table-head bg-[var(--table-head-bg)]">
              <tr>
                <th className="px-6 py-3.5 text-center text-xs font-semibold text-text">Violation ID</th>
                <th className="px-4 py-3.5 text-center text-xs font-semibold text-text">Severity</th>
                <th className="px-4 py-3.5 text-center text-xs font-semibold text-text">Type</th>
                <th className="px-4 py-3.5 text-center text-xs font-semibold text-text">Category</th>
                <th className="px-4 py-3.5 text-center text-xs font-semibold text-text">Provider</th>
                <th className="px-4 py-3.5 text-center text-xs font-semibold text-text">Title</th>
                <th className="px-4 py-3.5 text-center text-xs font-semibold text-text">File</th>
                <th className="px-4 py-3.5 text-center text-xs font-semibold text-text">Line</th>
                <th className="px-6 py-3.5 text-center text-xs font-semibold text-text">Action</th>
              </tr>
            </thead>

            <tbody className="divide-y divide-default">
              {pagedFindings.length > 0 ? (
                pagedFindings.map((finding, index) => {
                  const rowKey = `${finding.policyCode || "policy"}-${finding.file || "file"}-${finding.lineNo || "line"}-${index}`;
                  return (
                    <tr
                      key={rowKey}
                      className="group transition-colors hover:bg-elevated/40 border-b border-default"
                    >
                      <td className="px-6 py-3.5 align-middle text-left">
                        <span className="block font-mono text-xs font-bold text-[var(--text)] truncate text-left" title={finding.policyCode}>
                          {finding.policyCode}
                        </span>
                      </td>

                      <td className="px-4 py-3.5 align-middle text-left">
                        <SeverityBadge severity={finding.severity} />
                      </td>

                      <td className="px-4 py-3.5 align-middle text-left">
                        <div className="flex justify-start">
                          <TypeIconBadge type={finding.type} provider={finding.provider} />
                        </div>
                      </td>

                      <td className="px-4 py-3.5 align-middle text-left">
                        <span className="block text-xs uppercase text-[var(--text)] font-semibold truncate text-left" title={finding.category}>
                          {finding.category || "Uncategorized"}
                        </span>
                      </td>

                      <td className="px-4 py-3.5 align-middle text-left">
                        {finding.provider && finding.provider !== finding.type ? (
                          <div className="flex justify-start">
                            <ProviderIconBadge
                              provider={finding.provider}
                              className={getProviderBadgeStyle(finding.provider)}
                            />
                          </div>
                        ) : (
                          <span className="text-muted text-xs">—</span>
                        )}
                      </td>

                      <td className="px-4 py-3.5 align-middle max-w-[20rem] text-left">
                        <span className="block truncate text-xs font-semibold text-[var(--text)] text-left" title={finding.title}>
                          {finding.title || "N/A"}
                        </span>
                      </td>

                      <td className="px-4 py-3.5 align-middle text-left">
                        <span className="block truncate font-mono text-xs font-bold text-[var(--text)] text-left" title={finding.file}>
                          {getDisplayFileName(finding.file)}
                        </span>
                      </td>

                      <td className="px-4 py-3.5 align-middle text-left">
                        <span className="block font-mono text-xs font-semibold text-[var(--text)] text-left">
                          {getValidLineNumber(finding.lineNo) || "-"}
                        </span>
                      </td>

                      <td className="px-6 py-3.5 align-middle text-left">
                        <button
                          type="button"
                          onClick={(event) => {
                            event.stopPropagation();
                            handleFindingClick(finding);
                          }}
                          title="Expand finding details"
                          aria-label="Expand finding details"
                          className="inline-flex items-center gap-1 text-xs font-medium text-text hover:text-primary transition-colors whitespace-nowrap cursor-pointer"
                        >
                          <span>Expand</span>
                          <ChevronRight className="h-3.5 w-3.5" />
                        </button>
                      </td>
                    </tr>
                  );
                })
              ) : (
                <tr>
                  <td colSpan="9" className="px-3 py-12 text-left text-muted">
                    <div className="flex flex-col items-center gap-2">
                      <TechIcon name="file" size={32} color="var(--muted)" opacity={0.5} />
                      <p className="text-sm">No findings match your filter criteria</p>
                    </div>
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        {/* ── Figma Pagination Footer ── */}
        {findings.length > 0 && (
          <TablePagination
            currentPage={safePage}
            totalPages={totalPages}
            totalItems={findings.length}
            pageSize={pageSize}
            setPageSize={setPageSize}
            setCurrentPage={setCurrentPage}
            pageSizeOptions={PAGE_SIZE_OPTIONS}
          />
        )}
      </div>
    </>
  );
};

export default FindingsTable;