// components/iac-scan-dashboard.jsx
'use client';

import React, { useState, useMemo, useEffect } from "react";
import { useScanStore } from "@/store/useScanStore";
import { useNavbar } from "@/hooks/useNavbar";
import { AlertTriangle, AlertOctagon, Flame, ShieldCheck, GitBranch, Calendar, User, GitCommitHorizontal } from "lucide-react";
import dynamic from "next/dynamic";
import {
  LoadingState,
  ErrorState,
  EmptyState,
  FilterBar,
  FindingsTable,
} from "@/app/scanops/components/scan/iac";
import { processScanData } from "@/app/scanops/components/scan/iac/utils/dataProcessor";
import AIScannerPopup from "@/app/scanops/components/scan/shared/AIScannerPopup";
import TechStackIcon from "@/components/common/TechStackIcon";
import styles from "./IaC.module.css";

import IssuesBySeverityCard from "../components/scan/shared/IssuesBySeverityCard";
import SecurityScoreCard from "../components/scan/shared/SecurityScoreCard";
import ScanMetadataOverview from "../components/scan/shared/ScanMetadataOverview";

const BarChartUI = dynamic(() => import("@/components/charts/BarChartUI"), {
  ssr: false,
  loading: () => <div className={styles.chartLoading}>Loading Chart...</div>,
});
const PieChartUI = dynamic(() => import("@/components/charts/PieChartUI"), {
  ssr: false,
  loading: () => <div className={styles.chartLoading}>Loading Chart...</div>,
});
const HorizontalBarChart3D = dynamic(() => import("@/components/charts/HorizontalBarChart3D"), {
  ssr: false,
  loading: () => <div className={styles.chartLoading}>Loading Chart...</div>,
});

const IaCDashboard = ({ scanId }) => {
  const { latestScan, loading, error } = useScanStore();
  const { selectedInstallation } = useNavbar();
  const [selectedTypes, setSelectedTypes] = useState(["docker", "kubernetes", "terraform", "bicep", "arm", "ansible", "cloudformation"]);
  const [selectedSeverities, setSelectedSeverities] = useState(["critical", "high", "medium", "low"]);
  const [selectedProviders, setSelectedProviders] = useState([]);

  const getProviderKey = (finding) => {
    if (!finding.provider || finding.provider === finding.type) return "none";
    return String(finding.provider).toLowerCase();
  };

  // Process scan data for the dashboard
  const processedData = useMemo(() => {
    return processScanData(latestScan);
  }, [latestScan]);

  const providerOptions = useMemo(() => {
    if (!processedData?.iacFindings?.length) return [];

    const providerSet = new Set(processedData.iacFindings.map((finding) => getProviderKey(finding)));
    return Array.from(providerSet).sort((a, b) => {
      if (a === "none") return 1;
      if (b === "none") return -1;
      return a.localeCompare(b);
    });
  }, [processedData]);

  useEffect(() => {
    if (providerOptions.length === 0) {
      setSelectedProviders([]);
      return;
    }

    setSelectedProviders((prev) => {
      if (prev.length === 0) return providerOptions;

      const validSelections = prev.filter((provider) => providerOptions.includes(provider));
      return validSelections.length > 0 ? validSelections : providerOptions;
    });
  }, [providerOptions]);

  // Filter findings based on selected filters and active tab
  const filteredFindings = useMemo(() => {
    if (!processedData?.iacFindings) return [];

    return processedData.iacFindings.filter((finding) => {
      const matchesSeverity = selectedSeverities.includes(finding.severity);
      const matchesType = selectedTypes.includes(finding.type);
      const matchesProvider = selectedProviders.includes(getProviderKey(finding));

      return matchesSeverity && matchesType && matchesProvider;
    });
  }, [processedData, selectedSeverities, selectedTypes, selectedProviders]);

  const toggleSeverity = (severity) => {
    setSelectedSeverities((prev) =>
      prev.includes(severity) ? prev.filter((s) => s !== severity) : [...prev, severity]
    );
  };

  const toggleType = (type) => {
    setSelectedTypes((prev) => (prev.includes(type) ? prev.filter((t) => t !== type) : [...prev, type]));
  };

  const selectAllSeverities = () => {
    setSelectedSeverities(["critical", "high", "medium", "low"]);
  };

  const clearAllSeverities = () => {
    setSelectedSeverities([]);
  };

  const selectAllTypes = () => {
    setSelectedTypes(["docker", "kubernetes", "terraform", "bicep", "arm", "ansible", "cloudformation"]);
  };

  const clearAllTypes = () => {
    setSelectedTypes([]);
  };

  const toggleProvider = (provider) => {
    setSelectedProviders((prev) =>
      prev.includes(provider) ? prev.filter((item) => item !== provider) : [...prev, provider]
    );
  };

  const selectAllProviders = () => {
    setSelectedProviders(providerOptions);
  };

  const clearAllProviders = () => {
    setSelectedProviders([]);
  };

  if (loading) return <LoadingState />;
  if (error) return <ErrorState error={error} />;
  if (!processedData) return <EmptyState title="Scan Not Initiated" message="Start a new scan to find issues." />;
  if (processedData.iacFindings.length === 0)
    return <EmptyState message="No infrastructure as code security issues detected in this scan." />;

  const { iacSummary, severityData, issuesByTypeData } = processedData;

  const scanMetadata = latestScan?.scan_metadata || {};

  const metadataCards = [
    { label: "Repository", value: scanMetadata.repository || "N/A", icon: GitCommitHorizontal },
    { label: "Branch", value: scanMetadata.branch || "N/A", icon: GitBranch },
    { label: "Author", value: scanMetadata.commit_author || "N/A", icon: User },
    {
      label: "Scan Date", value: scanMetadata.scan_timestamp
        ? new Date(scanMetadata.scan_timestamp).toLocaleDateString()
        : "N/A", icon: Calendar
    },
  ];

  const kpiCards = [
    { title: "Total Issues", value: iacSummary.totalIssues, color: "#06B6D4", icon: AlertTriangle },
    { title: "Critical", value: iacSummary.bySeverity.critical, color: "#FB7185", icon: AlertOctagon },
    { title: "High", value: iacSummary.bySeverity.high, color: "#FB923C", icon: Flame },
    { title: "Medium", value: iacSummary.bySeverity.medium, color: "#FBBF24", icon: AlertTriangle },
    { title: "Low", value: iacSummary.bySeverity.low, color: "#22D3EE", icon: ShieldCheck },
  ];

  const providerChartData = [
    { name: "AWS", value: processedData.terraformAwsFindings?.length || 0, color: "#FB923C" },
    { name: "Azure", value: processedData.terraformAzureFindings?.length || 0, color: "#22D3EE" },
    { name: "GCP", value: processedData.terraformGcpFindings?.length || 0, color: "#22C55E" },
  ].filter((d) => d.value > 0);

  const iacScore =
    latestScan?.scan_results?.scan_results?.summary?.score_summary?.score_by_subscan?.iac ??
    latestScan?.scan_results?.scan_results?.summary?.score_summary?.overall_score ??
    (iacSummary.totalIssues === 0 ? 100 : Math.max(0, 100 - (iacSummary.bySeverity.critical * 25 + iacSummary.bySeverity.high * 15 + iacSummary.bySeverity.medium * 5 + iacSummary.bySeverity.low * 2)));

  return (
    <div className={styles.pageRoot}>
      <main className={styles.contentWrap}>

        <ScanMetadataOverview
          scanMetadata={scanMetadata}
          scanType="INFRASTRUCTURE AS CODE"
        />

        {/* ── CHARTS ─────────────────────────────────────── */}
        <section className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-6 items-stretch">
          <SecurityScoreCard score={iacScore} />
          <IssuesBySeverityCard severityData={severityData} title="Issues by Severity" />

          <article className={styles.panelCard}>
            <h3 style={{ margin: "0 0 4px", fontFamily: "var(--font-ui)", fontSize: "11px", fontWeight: 700, letterSpacing: "0.08em", textTransform: "uppercase", color: "var(--muted)" }}>Issues by IaC Type</h3>
            <p className="text-xs text-muted mb-3">Distribution across Docker, Kubernetes &amp; Terraform</p>
            <HorizontalBarChart3D
              data={issuesByTypeData.map((item) => ({
                name: item.name,
                value: item.issues,
                color: item.color,
              }))}
            />
          </article>

          {providerChartData.length > 0 && (
            <article className={`${styles.panelCard} lg:col-span-2 xl:col-span-3`}>
              <h3 style={{ margin: "0 0 4px", fontFamily: "var(--font-ui)", fontSize: "11px", fontWeight: 700, letterSpacing: "0.08em", textTransform: "uppercase", color: "var(--muted)" }}>Terraform Provider Distribution</h3>
              <p className="text-xs text-muted mb-3">Security issues across cloud providers</p>
              <BarChartUI
                data={providerChartData}
                height={220}
                colors={providerChartData.map((d) => d.color)}
                showLegend={false}
                showGrid
              />
            </article>
          )}
        </section>

        {/* ── FINDINGS TABLE ─────────────────────────────── */}
        <section className={styles.findingsShell}>
          <div className={styles.findingsHead}>
            <div>
              <h2>INFRASTRUCTURE AS CODE Findings</h2>
              <p>
                {filteredFindings.length} of {processedData.iacFindings.length} issue
                {processedData.iacFindings.length !== 1 ? "s" : ""} shown
              </p>
            </div>
          </div>

          <div style={{ padding: "16px 20px 8px", overflow: "visible" }}>
            <FilterBar
              selectedSeverities={selectedSeverities}
              selectedTypes={selectedTypes}
              toggleSeverity={toggleSeverity}
              toggleType={toggleType}
              selectAllSeverities={selectAllSeverities}
              clearAllSeverities={clearAllSeverities}
              selectAllTypes={selectAllTypes}
              clearAllTypes={clearAllTypes}
              selectedProviders={selectedProviders}
              providerOptions={providerOptions}
              toggleProvider={toggleProvider}
              selectAllProviders={selectAllProviders}
              clearAllProviders={clearAllProviders}
              totalIssues={filteredFindings.length}
            />
          </div>

          <div style={{ padding: "0 20px 20px" }}>
            <FindingsTable
              findings={filteredFindings}
              totalFindings={processedData.iacFindings.length}
              dockerCount={processedData.dockerFindings.length}
              kubernetesCount={processedData.kubernetesFindings.length}
              terraformCount={processedData.terraformFindings.length}
              terraformAwsCount={processedData.terraformAwsFindings.length}
              terraformAzureCount={processedData.terraformAzureFindings.length}
              terraformGcpCount={processedData.terraformGcpFindings.length}
              bicepCount={processedData.bicepFindings.length}
              armCount={processedData.armFindings.length}
              ansibleCount={processedData.ansibleFindings.length}
              cloudformationCount={processedData.cloudformationFindings.length}
              repositoryContext={{
                installationId:
                  selectedInstallation?.installationId ||
                  latestScan?.installation_id ||
                  scanMetadata.installation_id,
                repository: `${scanMetadata.organization || scanMetadata.org_name || ""}/${scanMetadata.repository || scanMetadata.repo_name || ""}`,
                branch: scanMetadata.branch || "main",
              }}
            />
          </div>
        </section>

      </main>

      <AIScannerPopup
        files={[...new Set((processedData?.iacFindings || []).map((f) => f.file).filter(Boolean))]}
      />
    </div>
  );
};

export default IaCDashboard;