'use client';

import React, { useMemo, useState } from "react";
import dynamic from "next/dynamic";
import { useSearchParams } from "next/navigation";
import { AlertCircle, AlertTriangle, FileCode2, FileSearch, ShieldAlert, Sparkles } from "lucide-react";
import { useScanStore } from "@/store/useScanStore";
import { useNavbar } from "@/hooks/useNavbar";
import {
  LoadingState,
  ErrorState,
  EmptyState,
  FilterBar,
  FindingsTable,
} from "@/app/scanops/components/scan/skill-scanner";
import { processScanData } from "@/app/scanops/components/scan/skill-scanner/utils/dataProcessor";
import CisScannerDashboard from "@/app/scanops/components/scan/cis/CisScanner";
import SecurityScoreCard from "@/app/scanops/components/scan/shared/SecurityScoreCard";
import ScanMetadataOverview from "@/app/scanops/components/scan/shared/ScanMetadataOverview";
import styles from "./SkillScanner.module.css";

const BarChartUI = dynamic(() => import("@/components/charts/BarChartUI"), { ssr: false });
const PieChartUI = dynamic(() => import("@/components/charts/PieChartUI"), { ssr: false });
const RadarChartUI = dynamic(() => import("@/components/charts/RadarChartUI"), { ssr: false });

const titleCase = (value) => String(value || "").replace(/[_-]+/g, " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
const countMapping = (mapping) => (mapping && typeof mapping === "object" ? Object.keys(mapping).length : 0);
const issueScannerValue = (mapping, keys) => {
  const item = Array.isArray(mapping) ? mapping[0] : mapping;
  return Number(keys.map((key) => item?.[key]).find((value) => value !== undefined) || 0);
};

const FrameworkStatusList = ({ items }) => (
  <div className={styles.mappingList}>
    {items.map((item) => {
      const gap = Number(item.gap || 0);
      const status = String(item.status || (gap === 0 ? "COMPLIANT" : "NON_COMPLIANT"));
      const statusClass = status === "COMPLIANT" || status === "PASS" ? styles.statusPass : gap >= 100 ? styles.statusFail : styles.statusWarn;
      return (
        <div className={styles.mappingRow} key={`${item.article}-${item.name}`}>
          <span className={`${styles.statusPill} ${statusClass}`}>{status === "COMPLIANT" ? "PASS" : status === "NON_COMPLIANT" ? "FAIL" : "WARN"}</span>
          <span className={styles.mappingName}>{item.name}</span>
          <span className={styles.mappingValue}>{status === "COMPLIANT" ? "PASSED" : `${gap} GAP${gap === 1 ? "" : "S"}`}</span>
        </div>
      );
    })}
  </div>
);

const OwaspGrid = ({ items }) => (
  <div className={styles.owaspGrid}>
    {items.map((item) => {
      const severity = String(item.severity || "medium").toLowerCase();
      return (
        <div className={styles.owaspItem} key={item.id}>
          <span className={styles.owaspId}>{item.id}</span>
          <span className={styles.owaspName}>{item.name}</span>
          <span className={`${styles.owaspSeverity} ${styles[`severity${severity}`]}`}>{severity}</span>
        </div>
      );
    })}
  </div>
);

function SkillScannerPanel() {
  const { latestScan, loading, error, startingScan, pollingScan } = useScanStore();
  const { selectedInstallation } = useNavbar();
  const [selectedSeverities, setSelectedSeverities] = useState(["critical", "high", "medium", "low"]);
  const [selectedTypes, setSelectedTypes] = useState([]);
  const [selectedCategories, setSelectedCategories] = useState([]);
  const processedData = useMemo(() => processScanData(latestScan), [latestScan]);

  if (startingScan || pollingScan) return <EmptyState title="Scan in Progress" message="Please wait while the AI Security scan completes." />;
  if (loading) return <LoadingState />;
  if (error) return <ErrorState error={error} />;
  if (!processedData) return <EmptyState title="Scan Not Initiated" message="Start a new AI Security scan using the New Scan button above." />;
  if (processedData.scannerSummary.findingsCount === 0 && processedData.skillFindings.length === 0) {
    return <EmptyState title="No AI Security Issues Found" message="No violations were detected in this scan." />;
  }

  const { severityData, typeOptions, categoryOptions, categoryCounts, frameworkMappings, skillResult, scannerSummary } = processedData;
  const euItems = frameworkMappings.euAiAct?.items || [];
  const nist = frameworkMappings.nist || {};
  const mitre = frameworkMappings.mitre || {};
  const owasp = frameworkMappings.owasp || [];
  const filteredFindings = processedData.skillFindings.filter((finding) => (
    selectedSeverities.includes(finding.severity) &&
    (selectedTypes.length === 0 || selectedTypes.includes(finding.type)) &&
    (selectedCategories.length === 0 || selectedCategories.includes(finding.category))
  ));
  const scanMetadata = processedData.scanMetadata;
  const skillScore =
    skillResult?.metadata?.overall_score ??
    latestScan?.scan_results?.scan_results?.summary?.score_summary?.score_by_subscan?.["skill-scanner"] ??
    latestScan?.scan_results?.scan_results?.summary?.score_summary?.overall_score ??
    (scannerSummary.findingsCount === 0 ? 100 : Math.max(0, 100 - (scannerSummary.severityBreakdown.critical * 25 + scannerSummary.severityBreakdown.high * 15 + scannerSummary.severityBreakdown.medium * 5 + scannerSummary.severityBreakdown.low * 2)));
  const scannerChartData = [
    { name: "EU AI ACT", value: issueScannerValue(frameworkMappings.issueByScanner, ["eu_ai_act", "eu_ai_act_mapping"]), color: "#2DC875" },
    { name: "NIST AI RMF", value: issueScannerValue(frameworkMappings.issueByScanner, ["nist_act", "nist_ai_rmf"]), color: "#FFC400" },
    { name: "MITRE ATLAS", value: issueScannerValue(frameworkMappings.issueByScanner, ["mitre_act", "mitre_atlas"]), color: "#FFC400" },
    { name: "OWASP Agentic AI", value: issueScannerValue(frameworkMappings.issueByScanner, ["owasp_act", "owasp_agentic"]), color: "#FFC400" },
  ];
  const mitreChartData = Object.entries(mitre).map(([name, value]) => ({ name: titleCase(name), value: Number(value) || 0 }));
  const nistChartData = ["govern", "map", "measure", "manage"].map((subject) => ({ subject: titleCase(subject), value: Number(nist[subject]) || 0 }));
  const overallProgress = Number(frameworkMappings.euAiAct?.overall_progress || 0);
  const summaryCards = [
    { label: "AI Skills Discovered", value: scannerSummary.filesScanned, icon: FileSearch, accent: "#06B6D4" },
    { label: "Total Issues", value: scannerSummary.findingsCount, icon: ShieldAlert, accent: "#F97316" },
    { label: "Critical", value: scannerSummary.severityBreakdown.critical, icon: AlertCircle, accent: "#EF4444" },
    { label: "High", value: scannerSummary.severityBreakdown.high, icon: AlertTriangle, accent: "#F97316" },
    { label: "Medium", value: scannerSummary.severityBreakdown.medium, icon: AlertTriangle, accent: "#EAB308" },
    { label: "Low", value: scannerSummary.severityBreakdown.low, icon: Sparkles, accent: "#06B6D4" },
  ];

  const toggleSeverity = (severity) => setSelectedSeverities((current) => current.includes(severity) ? current.filter((item) => item !== severity) : [...current, severity]);
  const toggleType = (type) => setSelectedTypes((current) => current.includes(type) ? current.filter((item) => item !== type) : [...current, type]);
  const selectAllSeverities = () => setSelectedSeverities(["critical", "high", "medium", "low"]);
  const clearAllSeverities = () => setSelectedSeverities([]);
  const selectAllTypes = () => setSelectedTypes(typeOptions.map((type) => type.id));
  const clearAllTypes = () => setSelectedTypes([]);
  const toggleCategory = (category) => setSelectedCategories((current) => current.includes(category) ? current.filter((item) => item !== category) : [...current, category]);
  const selectAllCategories = () => setSelectedCategories(categoryOptions.map((category) => category.id));
  const clearAllCategories = () => setSelectedCategories([]);

  return (
    <div className={styles.pageRoot}>
      <main className={styles.contentWrap}>
        <ScanMetadataOverview
          scanMetadata={scanMetadata}
          scanType="AI SECURITY SCANNER"
          duration={scanMetadata.scan_timestamp ? new Date(scanMetadata.scan_timestamp).toLocaleDateString() : "N/A"}
        />

        <section className={styles.kpiGrid} aria-label="AI Security Scanner summary">
          {summaryCards.map(({ label, value, icon: Icon, accent }) => (
            <article className={styles.kpiCard} style={{ "--kpi-accent": accent }} key={label}>
              <span className={styles.kpiIcon}><Icon size={19} strokeWidth={1.8} /></span>
              <div className={styles.kpiContent}>
                <strong>{value}</strong>
                <p>{label}</p>
              </div>
            </article>
          ))}
        </section>

        <section className={styles.chartGrid}>
          <SecurityScoreCard score={skillScore} />
          <article className={styles.panelCard}>
            <div className={styles.panelEyebrow}>Issues by severity</div>
            <div className={styles.severityChartRow}><PieChartUI data={severityData} height={210} showCenterText={false} showLegend={false} /><div className={styles.severityLegend}>{severityData.map((item) => <div key={item.name} className={styles.legendRow}><span className={styles.legendDot} style={{ background: item.color }} /> <span>{item.name}:</span><strong>{item.value}</strong></div>)}</div></div>
          </article>
          <article className={styles.panelCard}><div className={styles.panelEyebrow}>Issue by scanner</div><BarChartUI data={scannerChartData} dataKey="value" nameKey="name" height={220} barSize={18} colors={scannerChartData.map((item) => item.color)} showLegend={false} showGrid /></article>

          <article className={styles.panelCard}><div className={styles.panelEyebrow}>Regulatory <strong>EU AI Act Mapping</strong></div><FrameworkStatusList items={euItems} /><div className={styles.overallLabel}><span>Overall</span><strong>{overallProgress}%</strong></div><div className={styles.progressTrack}><span style={{ width: `${Math.min(100, Math.max(0, overallProgress))}%` }} /></div></article>
          <article className={styles.panelCard}><div className={styles.panelEyebrow}>Govern · Map · Measure · Manage <strong>NIST AI RMF</strong></div><RadarChartUI data={nistChartData} height={210} colors={["#22C55E"]} showGlow={false} /><div className={styles.metricStrip}>{nistChartData.map((item) => <div key={item.subject}><span>{item.subject}</span><strong>{item.value}%</strong></div>)}</div></article>

          <article className={styles.panelCard}><div className={styles.panelEyebrow}>Attack tactics <strong>MITRE ATLAS Coverage</strong></div><div className={styles.tacticList}>{mitreChartData.map((item) => <div className={styles.tacticRow} key={item.name}><div><span>{item.name}</span><strong>{item.value}%</strong></div><div className={styles.progressTrack}><span style={{ width: `${Math.min(100, Math.max(0, item.value))}%` }} /></div></div>)}</div></article>
          <article className={styles.panelCard}><div className={styles.panelEyebrow}>Open standard <strong>OWASP Agentic AI Top 10</strong></div>{owasp.length ? <OwaspGrid items={owasp} /> : <div className={styles.emptyResult}>No OWASP mappings available.</div>}</article>
        </section>

        <section className={styles.findingsShell}>
          <div className={styles.findingsHead}><div><h2>Skill findings</h2><p>{filteredFindings.length} of {processedData.skillFindings.length} findings shown</p></div></div>
          <div style={{ padding: "16px 20px 8px", overflow: "visible" }}><FilterBar selectedSeverities={selectedSeverities} selectedTypes={selectedTypes} typeOptions={typeOptions} selectedCategories={selectedCategories} categoryOptions={categoryOptions} toggleSeverity={toggleSeverity} toggleType={toggleType} toggleCategory={toggleCategory} selectAllSeverities={selectAllSeverities} clearAllSeverities={clearAllSeverities} selectAllTypes={selectAllTypes} clearAllTypes={clearAllTypes} selectAllCategories={selectAllCategories} clearAllCategories={clearAllCategories} selectedProviders={[]} providerOptions={[]} totalIssues={filteredFindings.length} /></div>
          <div style={{ padding: "0 20px 20px" }}>
            <FindingsTable
              findings={filteredFindings}
              totalFindings={processedData.skillFindings.length}
              repositoryContext={{
                installationId: selectedInstallation?.installationId || latestScan?.installation_id,
                repository: `${scanMetadata.organization || scanMetadata.org_name || ""}/${scanMetadata.repository || scanMetadata.repo_name || ""}`,
                branch: scanMetadata.branch || "main",
              }}
            />
          </div>
        </section>
      </main>
    </div>
  );
}

// The CIS Scanner is its own backend scan (scan type "cis-agent") that shares
// this page with the AI Security Scanner. The tab switcher lives in the scan
// header (scanops/layout.js); the active tab is the ?tab=cis URL param, which
// also selects the scan type for New Scan / Refresh / latest-scan fetching.
export default function AISecurityScannerDashboard() {
  const isCisTab = useSearchParams().get("tab") === "cis";
  return isCisTab ? <CisScannerDashboard /> : <SkillScannerPanel />;
}
