"use client";
// Main Sbom component logic extracted from Sbom.js
import React, { useState, useEffect } from "react";
import { Package, Building2, FolderGit2, GitBranch, Sun } from "lucide-react";
import { useScanStore } from "@/store/useScanStore";
import LoadingState from "../workflow/LoadingState";
import ErrorState from "../workflow/ErrorState";
import EmptyState from "./EmptyState";
import SbomRiskCharts from "./SbomRiskCharts";
import SbomMainTable from "./SbomMainTable";
import SbomPagination from "./SbomPagination";
import * as sbomUtils from "./utils";
import styles from "./Sbom.module.css";

const Sbom = () => {
  const { latestScan, loading, error } = useScanStore();
  if (loading) return <LoadingState />;
  if (error) return <ErrorState error={error} />;
  if (!latestScan) return <EmptyState title="Scan Not Initiated" message="Start a new scan to find issues." />;

  // --- All helper logic moved to sbomUtils ---
  const sbomData = sbomUtils.getSbomData(latestScan);
  const sbomScanner = sbomUtils.getSbomScanner(latestScan);
  const scanMetadata = latestScan?.scan_metadata || {};
  const scanTime = scanMetadata.scan_timestamp || scanMetadata.created_at;
  const securityScore = sbomUtils.toFiniteNumber(latestScan?.scan_results?.scan_results?.summary?.score_summary?.score_by_subscan?.sbom, 0);
  const boundedScore = Math.max(0, Math.min(100, Math.round(securityScore)));
  const scoreColor = sbomUtils.getScoreColor(boundedScore);
  const ringRadius = 42;
  const ringCircumference = 2 * Math.PI * ringRadius;
  const ringOffset = ringCircumference * (1 - boundedScore / 100);
  const metadataCards = sbomUtils.getMetadataCards(scanMetadata);
  const repositoryName = scanMetadata.repository || scanMetadata.repo_name || "N/A";
  const accountName = scanMetadata.organization || scanMetadata.org_name || scanMetadata.owner || "N/A";
  const branchName = scanMetadata.branch || scanMetadata.branch_name || "main";
  const [currentPage, setCurrentPage] = useState(1);
  const [searchTerm, setSearchTerm] = useState("");
  const [licenseFilter, setLicenseFilter] = useState("all");
  const [packageManagerFilter, setPackageManagerFilter] = useState("all");
  const [languageFilter, setLanguageFilter] = useState("all");
  const [riskLevelFilter, setRiskLevelFilter] = useState("all");
  const [approvalStatusFilter, setApprovalStatusFilter] = useState("all");
  const [sortConfig, setSortConfig] = useState({ key: null, direction: "asc" });
  const [viewMode, setViewMode] = useState("table");
  useEffect(() => { setCurrentPage(1); }, [searchTerm, licenseFilter, packageManagerFilter, languageFilter, riskLevelFilter, approvalStatusFilter]);
  const chartColors = sbomUtils.getChartColors();
  const CHART_SERIES = sbomUtils.getChartSeries(chartColors);
  const packages = sbomData;
  const uniqueLicenses = sbomUtils.getUniqueLicenses(packages, sbomScanner);
  const uniquePackageManagers = sbomUtils.getUniquePackageManagers(packages, sbomScanner);
  const uniqueLanguages = sbomUtils.getUniqueLanguages(packages);
  const uniqueRiskLevels = sbomUtils.getUniqueRiskLevels(packages);
  const uniqueApprovalStatuses = sbomUtils.getUniqueApprovalStatuses(packages);
  const complianceStats = sbomUtils.getComplianceStats(packages, sbomScanner);
  const chartData = sbomUtils.getChartData(packages, complianceStats, CHART_SERIES);
  const filteredAndSortedPackages = sbomUtils.getFilteredAndSortedPackages(packages, searchTerm, licenseFilter, packageManagerFilter, languageFilter, riskLevelFilter, approvalStatusFilter, sortConfig);
  const ITEMS_PER_PAGE = viewMode === "table" ? sbomUtils.CONFIG.LAYOUT.TABLE_ITEMS_PER_PAGE : sbomUtils.CONFIG.LAYOUT.GRID_ITEMS_PER_PAGE;
  const totalPages = Math.ceil(filteredAndSortedPackages.length / ITEMS_PER_PAGE);
  const paginatedPackages = filteredAndSortedPackages.slice((currentPage - 1) * ITEMS_PER_PAGE, currentPage * ITEMS_PER_PAGE);
  if (packages.length === 0) return <EmptyState />;
  return (
    <div className={styles.pageRoot}>
      <div className={styles.sbomShell}>
        <main className={styles.contentWrap}>
          <section className={styles.heroCard}>
            <div className={styles.heroTop}>
              <div>
                <div className={styles.heroTitleWrap}>
                  <span className={styles.heroIcon}><Package size={20} /></span>
                  <h1 className={styles.heroTitle}>Software Bill of Materials</h1>
                </div>
                <p className={styles.heroSubtitle}>
                  Comprehensive dependency analysis and license compliance tracking
                </p>
                <p className={styles.heroMetaTime}>Last scanned: {sbomUtils.formatDateTime(scanTime)}</p>
              </div>
              <div className={styles.scoreRing} role="img" aria-label={`Security score ${boundedScore} out of 100`}>
                <svg className={styles.scoreSvg} viewBox="0 0 100 100" aria-hidden="true">
                  <circle className={styles.scoreTrack} cx="50" cy="50" r={ringRadius} />
                  <circle
                    className={styles.scoreProgress}
                    cx="50"
                    cy="50"
                    r={ringRadius}
                    style={{ stroke: scoreColor, strokeDasharray: `${ringCircumference}`, strokeDashoffset: ringOffset }}
                  />
                </svg>
                <div className={styles.scoreCenter}>
                  <strong style={{ color: scoreColor }}>{boundedScore}</strong>
                  <span>Security Score</span>
                </div>
              </div>
            </div>
            <div className={styles.metaGrid}>
              {metadataCards.map((item) => (
                <div key={item.label} className={styles.metaItem}>
                  <span className={styles.metaLabel}>
                    <item.icon size={10} /> {item.label}
                  </span>
                  <span className={styles.metaValue}>{item.value}</span>
                </div>
              ))}
            </div>
          </section>
          <SbomRiskCharts licenseTypes={chartData.licenseTypes} packageManagers={chartData.packageManagers} />
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
            riskLevelFilter={riskLevelFilter}
            setRiskLevelFilter={setRiskLevelFilter}
            uniqueRiskLevels={uniqueRiskLevels}
            approvalStatusFilter={approvalStatusFilter}
            setApprovalStatusFilter={setApprovalStatusFilter}
            uniqueApprovalStatuses={uniqueApprovalStatuses}
            sortConfig={sortConfig}
            setSortConfig={setSortConfig}
            paginatedPackages={paginatedPackages}
            getLicenseInfo={sbomUtils.getLicenseInfo}
            getDisplayRiskLevel={sbomUtils.getDisplayRiskLevel}
            getRiskColor={sbomUtils.getRiskColor}
            formatLicenseName={sbomUtils.formatLicenseName}
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
    </div>
  );
};

export default Sbom;
