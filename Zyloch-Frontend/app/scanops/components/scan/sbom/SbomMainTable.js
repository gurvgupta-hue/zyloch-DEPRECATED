import React, { useRef } from "react";
import Link from "next/link";
import { Search, ChevronsUpDown, ArrowUpDown, Package, ExternalLink, Tag, ShieldCheck, FileText, ChevronRight, Filter } from "lucide-react";
import Tooltip from "@mui/material/Tooltip";
import RiskBadge from "./RiskBadge";
import { useInteractiveTable } from "../shared/useInteractiveTable";
import { resolvePackageUrl } from "./utils";
import styles from "./Sbom.module.css";

const SbomMainTable = React.memo(function SbomMainTable({
  filteredAndSortedPackages,
  searchTerm,
  setSearchTerm,
  setCurrentPage,
  currentPage,
  itemsPerPage,
  packageManagerFilter,
  setPackageManagerFilter,
  uniquePackageManagers,
  riskLevelFilter,
  setRiskLevelFilter,
  uniqueRiskLevels,
  approvalStatusFilter,
  setApprovalStatusFilter,
  uniqueApprovalStatuses,
  sortConfig,
  setSortConfig,
  paginatedPackages,
  getLicenseInfo,
  getDisplayRiskLevel,
  getRiskColor,
  formatLicenseName
}) {
  const tableContainerRef = useRef(null);

  useInteractiveTable({
    containerRef: tableContainerRef,
    storageKey: "scanops-sbom-main-table",
    minWidth: 96,
    deps: [paginatedPackages.length],
  });

  return (
    <section className={styles.findingsShell}>
      <div className={styles.findingsTopFrame}>
        <div className={styles.findingsHead}>
          <div>
            <h2>SBOM SCANNER FINDINGS</h2>
            <p>
              {filteredAndSortedPackages.length > 0
                ? `Showing ${(currentPage - 1) * itemsPerPage + 1}-${Math.min(currentPage * itemsPerPage, filteredAndSortedPackages.length)} of ${filteredAndSortedPackages.length} results`
                : `Showing 0 of ${filteredAndSortedPackages.length} results`}
            </p>
          </div>
          <div className={styles.searchWrap}>
            <label className={styles.searchBox}>
              <Search size={12} />
              <input
                type="text"
                placeholder="Search by CVE ID or package name (e.g. CVE-2024-1234, lodash)..."
                value={searchTerm}
                onChange={(e) => {
                  setSearchTerm(e.target.value);
                  setCurrentPage(1);
                }}
              />
            </label>
          </div>
        </div>
      </div>

      <div className={styles.filterFrame}>
        <div className={styles.filterRow}>
          <span className="text-xs font-medium uppercase tracking-wider text-muted select-none mr-1">
            FILTERS
          </span>
          <div className={styles.filterSelectWrap}>
            <select
              value={riskLevelFilter}
              onChange={(e) => {
                setRiskLevelFilter(e.target.value);
                setCurrentPage(1);
              }}
              className={styles.selectControl}
            >
              <option value="all">Licensing Risk: All</option>
              {uniqueRiskLevels.map((risk) => (
                <option key={`risk-${risk}`} value={risk}>{`Licensing Risk: ${risk}`}</option>
              ))}
            </select>
            <ChevronsUpDown size={12} className={styles.selectIcon} />
          </div>

          <div className={styles.filterSelectWrap}>
            <select
              value={approvalStatusFilter}
              onChange={(e) => {
                setApprovalStatusFilter(e.target.value);
                setCurrentPage(1);
              }}
              className={styles.selectControl}
            >
              <option value="all">OSS Risk: All</option>
              {uniqueApprovalStatuses.map((status) => (
                <option key={`oss-${status}`} value={status}>{status}</option>
              ))}
            </select>
            <ChevronsUpDown size={12} className={styles.selectIcon} />
          </div>

          <div className={styles.filterSelectWrap}>
            <select
              value={sortConfig?.key || "moduleName"}
              onChange={(e) => {
                const nextKey = e.target.value;
                setSortConfig({ key: nextKey, direction: "asc" });
                setCurrentPage(1);
              }}
              className={styles.selectControl}
            >
              <option value="moduleName">Sort Rows: Package</option>
              <option value="versionInfo">Sort Rows: Version</option>
              <option value="licenseConcluded">Sort Rows: License</option>
            </select>
            <ArrowUpDown size={12} className={styles.selectIcon} />
          </div>

          <div className={styles.filterSelectWrap}>
            <select
              value={packageManagerFilter}
              onChange={(e) => {
                setPackageManagerFilter(e.target.value);
                setCurrentPage(1);
              }}
              className={styles.selectControl}
            >
              <option value="all">Manager: All</option>
              {uniquePackageManagers.map((manager) => (
                <option key={`mgr-${manager}`} value={manager}>{manager}</option>
              ))}
            </select>
            <ChevronsUpDown size={12} className={styles.selectIcon} />
          </div>
        </div>
      </div>

      <div className={styles.findingsList}>
        <div className="overflow-x-auto" ref={tableContainerRef}>
          <table className={styles.sbomTable}>
            <colgroup>
              <col style={{ width: "22%" }} />
              <col style={{ width: "10%" }} />
              <col style={{ width: "14%" }} />
              <col style={{ width: "14%" }} />
              <col style={{ width: "10%" }} />
              <col style={{ width: "16%" }} />
              <col style={{ width: "14%" }} />
            </colgroup>
            <thead className={styles.tableHead}>
              <tr>
                <th>Package Name</th>
                <th>Version</th>
                <th>License</th>
                <th>Licensing Risk</th>
                <th>Link</th>
                <th>OSS Risk</th>
                <th>CVE ID</th>
              </tr>
            </thead>
            <tbody>
              {paginatedPackages.map((pkg, i) => {
                const licenseInfo = getLicenseInfo(pkg.licenseConcluded);
                const cveId = (pkg.cveId || "").trim();
                const packageEcosystem = (pkg.packageManager || "npm").trim();
                const cveDetailsHref = cveId
                  ? {
                    pathname: `/scanops/cve/${encodeURIComponent(cveId)}`,
                    query: {
                      pkg: pkg.moduleName || "",
                      version: pkg.versionInfo || "",
                      affectedVersion:
                        pkg.affectedVersion ||
                        pkg.affected_version ||
                        pkg.affected ||
                        pkg.vulnerableVersion ||
                        pkg.vulnerable_version ||
                        pkg.vulnerableVersions ||
                        pkg.vulnerable_versions ||
                        pkg.affectedRange ||
                        pkg.affected_range ||
                        pkg.versionRange ||
                        pkg.version_range ||
                        "",
                      fixedVersion:
                        pkg.fixedVersion ||
                        pkg.fixed_version ||
                        pkg.fixVersion ||
                        pkg.fix_version ||
                        pkg.patchedVersion ||
                        pkg.patched_version ||
                        pkg.firstPatchedVersion ||
                        pkg.first_patched_version ||
                        pkg.patched ||
                        "",
                      ecosystem: packageEcosystem,
                      file: pkg.sourceLocation || "",
                      codeBlock: pkg.codeBlock || pkg.sourceContext || "",
                      severity: pkg.severity || "",
                      priority: pkg.ossRisk || pkg.severity || "",
                      ossRisk: pkg.ossRisk || pkg.severity || licenseInfo.approvalStatus || "",
                      reachability: pkg.reachability || "Not Reachable",
                      cve: cveId,
                      cvss: pkg.cvssScore || "",
                      epss: pkg.epssScore || "",
                      kev: pkg.kev || "",
                      cwe: Array.isArray(pkg.cweIds) ? pkg.cweIds.join(",") : "",
                      published: pkg.published || "",
                      patched:
                        pkg.patched ||
                        pkg.patchedVersion ||
                        pkg.patched_version ||
                        pkg.firstPatchedVersion ||
                        pkg.first_patched_version ||
                        pkg.fix_version ||
                        "",
                      description: pkg.description || ""
                    }
                  }
                  : null;
                const isUnknownLicense = !pkg.licenseConcluded || pkg.licenseConcluded === "UNKNOWN" || pkg.licenseConcluded.toLowerCase() === "other";
                const getLicenseDisplayColor = () => {
                  const licenseText = (pkg.licenseConcluded || "").toLowerCase();
                  if (isUnknownLicense) return "var(--warning)";
                  if (licenseText.includes('apache')) return "var(--info)";
                  if (licenseText.includes('bsd')) return "var(--color-primary)";
                  if (licenseText.includes('mit')) return "var(--success)";
                  return "var(--success)";
                };
                const displayRiskLevel = getDisplayRiskLevel(pkg);
                const riskColorConfig = getRiskColor(displayRiskLevel);
                const packageRegistryUrl = resolvePackageUrl(pkg);
                return (
                  <tr key={i}>
                    <td>
                      <div className={styles.pkgCell}>
                        <span className={styles.pkgIcon}>
                          <Package size={16} />
                        </span>
                        <span className={styles.pkgName}>{pkg.moduleName}</span>
                      </div>
                    </td>
                    <td>
                      <span className={styles.versionChip}>
                        {pkg.versionInfo || "-"}
                      </span>
                    </td>
                    <td>
                      {(() => {
                        const lic = formatLicenseName(pkg.licenseConcluded);
                        const isUnknown = !lic || lic === "Unknown";
                        return (
                          <span
                            className={styles.licenseText}
                            style={{ color: isUnknown ? "var(--muted)" : getLicenseDisplayColor() }}
                          >
                            {isUnknown ? "-" : lic}
                          </span>
                        );
                      })()}
                    </td>
                    <td>
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
                        <div className={styles.riskBadgeWrap}>
                          <RiskBadge riskLevel={displayRiskLevel} colorConfig={riskColorConfig} />
                        </div>
                      </Tooltip>
                    </td>
                    <td>
                      {packageRegistryUrl ? (
                        <a href={packageRegistryUrl} target="_blank" rel="noopener noreferrer" className={styles.viewLink}>
                          <ExternalLink size={14} />
                          <span>View</span>
                        </a>
                      ) : (
                        <span className={styles.emptyLink}>-</span>
                      )}
                    </td>
                    <td>
                      {(() => {
                        const sev = pkg.ossRisk;
                        const sevColor =
                          sev === "Immediate" ? "var(--danger)" :
                            sev === "Critical" ? "var(--danger)" :
                              sev === "High" ? "#f97316" :
                                sev === "Medium" ? "var(--warning)" :
                                  sev === "Low" ? "var(--success)" :
                                    sev === "Monitor" ? "var(--info)" :
                                      "var(--muted)";
                        const sevBg =
                          sev === "Immediate" ? "color-mix(in srgb, var(--danger) 12%, transparent)" :
                            sev === "Critical" ? "color-mix(in srgb, var(--danger) 12%, transparent)" :
                              sev === "High" ? "color-mix(in srgb, #f97316 12%, transparent)" :
                                sev === "Medium" ? "color-mix(in srgb, var(--warning) 12%, transparent)" :
                                  sev === "Low" ? "color-mix(in srgb, var(--success) 12%, transparent)" :
                                    sev === "Monitor" ? "color-mix(in srgb, var(--info) 12%, transparent)" :
                                      "color-mix(in srgb, var(--muted) 12%, transparent)";
                        return (
                          <span style={{
                            display: "inline-block",
                            padding: "3px 10px",
                            borderRadius: "6px",
                            fontSize: "11px",
                            fontWeight: 600,
                            letterSpacing: "0.04em",
                            color: sevColor,
                            background: sevBg,
                            border: `1px solid ${sevColor}`,
                            textTransform: "uppercase",
                          }}>
                            {sev || "-"}
                          </span>
                        );
                      })()}
                    </td>
                    <td>
                      <div style={{ display: "flex", alignItems: "center", gap: "6px", flexWrap: "wrap" }}>
                        {cveDetailsHref ? (
                          <Link href={cveDetailsHref} className={styles.cveLink}>
                            <span>{cveId}</span>
                            <ChevronRight size={12} aria-hidden="true" />
                          </Link>
                        ) : (
                          <span className={styles.cveText}>-</span>
                        )}
                      </div>
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

export default SbomMainTable;
