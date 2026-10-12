"use client";

import React, { useMemo, useState } from "react";
import { useNavbar } from "@/hooks/useNavbar";
import { useScanStore } from "@/store/useScanStore";
import { FileCode2, FolderGit2, GitBranch, GitCommitHorizontal, ScanSearch, UserRound, Clock3 } from "lucide-react";
import TechStackIcon from "@/components/common/TechStackIcon";
import Section from "../overview/metrics/Section";
import InfoCard from "../overview/metrics/InfoCard";
import StatCard from "../overview/metrics/StatCard";
import { formatApiText, formatDuration } from "../overview/utils";
import { OVERVIEW_DS } from "../overview/designSystem";
import { LoadingState, ErrorState, EmptyState, FilterBar, FindingsTable } from "../skill-scanner";
import { processCisScanData } from "./utils/dataProcessor";
import ComplianceRing from "./ComplianceRing";
import SeverityFunnel from "./SeverityFunnel";
import ControlBreakdown from "./ControlBreakdown";

// Reads the shared scan store: scanops/layout.js fetches (and starts/refreshes)
// the `cis-agent` scan while ?tab=cis is active, so latestScan is the CIS scan.
export default function CisScannerDashboard() {
  const { latestScan, loading, error, startingScan, pollingScan } = useScanStore();
  const { selectedInstallation } = useNavbar();
  const [selectedSeverities, setSelectedSeverities] = useState(["critical", "high", "medium", "low"]);
  const [selectedTypes, setSelectedTypes] = useState([]);
  const processedData = useMemo(() => processCisScanData(latestScan), [latestScan]);

  if (startingScan || pollingScan) return <EmptyState title="Scan in Progress" message="Please wait while the CIS scan completes." />;
  if (loading) return <LoadingState />;
  if (error) return <ErrorState error={error} />;
  if (!processedData) return <EmptyState title="Scan Not Initiated" message="Start a new CIS scan using the New Scan button above." />;
  if (processedData.scannerSummary.findingsCount === 0 && processedData.cisFindings.length === 0) {
    return <EmptyState title="No CIS Violations Found" message="No CIS AI Agents Companion Guide violations were detected in this scan." />;
  }

  const { scannerSummary, severityData, controlData, totalControlFindings, cisFindings, typeOptions, scanMetadata } = processedData;

  const filteredFindings = cisFindings.filter((finding) => (
    selectedSeverities.includes(finding.severity) &&
    (selectedTypes.length === 0 || selectedTypes.includes(finding.type))
  ));

  const repositoryName = [scanMetadata.organization, scanMetadata.repository].filter(Boolean).join("/") || scanMetadata.repository || "N/A";
  const branchName = scanMetadata.branch || "N/A";
  const commitMessage = String(scanMetadata.commit_message ?? "").trim() || "N/A";
  const commitAuthor = String(scanMetadata.commit_author ?? "").trim() || "N/A";
  const authorInitial = commitAuthor?.trim()?.charAt(0)?.toUpperCase() || "N";

  const repositoryOverviewCards = [
    { label: "Last Commit", value: commitMessage, icon: <GitCommitHorizontal /> },
    {
      label: "Commit Author",
      value: (
        <div className="inline-flex items-center gap-2 min-w-0">
          <span className="inline-flex h-6 w-6 items-center justify-center rounded-full bg-[color-mix(in_srgb,var(--color-primary)_14%,var(--surface))] text-xs font-semibold text-[var(--color-primary)]">
            {authorInitial}
          </span>
          <span className="truncate text-base font-semibold leading-tight text-[var(--text)]">{commitAuthor}</span>
        </div>
      ),
      icon: <UserRound />,
    },
    { label: "Scan Type", value: "CIS", icon: <ScanSearch /> },
    { label: "Event Type", value: formatApiText(scanMetadata.event_type || "N/A"), icon: <GitBranch /> },
    { label: "Duration", value: formatDuration(scannerSummary.duration), icon: <Clock3 /> },
  ];

  const toggleSeverity = (severity) => setSelectedSeverities((current) => current.includes(severity) ? current.filter((item) => item !== severity) : [...current, severity]);
  const selectAllSeverities = () => setSelectedSeverities(["critical", "high", "medium", "low"]);
  const clearAllSeverities = () => setSelectedSeverities([]);
  const toggleType = (type) => setSelectedTypes((current) => current.includes(type) ? current.filter((item) => item !== type) : [...current, type]);
  const selectAllTypes = () => setSelectedTypes(typeOptions.map((type) => type.id));
  const clearAllTypes = () => setSelectedTypes([]);

  const findingsBySeverityTotal = severityData.reduce((sum, item) => sum + item.value, 0);
  const criticalCount = scannerSummary.severityBreakdown.critical || 0;

  return (
    <div className="space-y-6 p-4">
      {/* Repository Overview */}
      <Section>
        <div className="space-y-4">
          <div className="flex flex-wrap items-center gap-3 text-sm md:text-base">
            <div className="flex items-center gap-2 whitespace-nowrap">
              <span className="inline-flex h-8 w-8 items-center justify-center rounded-lg bg-[color-mix(in_srgb,var(--color-primary)_14%,var(--surface))]">
                <TechStackIcon name="github" size={18} />
              </span>
              <span className="font-semibold text-[var(--text)]" style={{ fontFamily: OVERVIEW_DS.typography.family, fontSize: OVERVIEW_DS.typography.body }}>
                Repository Overview
              </span>
            </div>
            <span className="break-all font-semibold text-[var(--muted)]" style={{ fontFamily: OVERVIEW_DS.typography.family, fontSize: OVERVIEW_DS.typography.label }}>
              {repositoryName}
            </span>
            <span className="font-semibold text-[var(--muted)]" style={{ fontFamily: OVERVIEW_DS.typography.family, fontSize: OVERVIEW_DS.typography.micro }}>
              {branchName}
            </span>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-5 gap-4 border-t border-[var(--border)] pt-4">
            {repositoryOverviewCards.map((card) => (
              <InfoCard key={card.label} label={card.label} value={card.value} icon={card.icon} />
            ))}
          </div>
        </div>
      </Section>

      {/* KPI row */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div
          className="rounded-2xl border border-[var(--border)] bg-[var(--surface)] p-5"
          style={{ boxShadow: "var(--shadow-2)" }}
        >
          <p className="text-xs font-medium text-[var(--muted)]">Compliance score</p>
          <div className="mt-2">
            <ComplianceRing score={scannerSummary.overallScore} />
          </div>
        </div>

        <StatCard
          label="Total findings"
          value={scannerSummary.findingsCount}
          icon={FileCode2}
          color="var(--high)"
          status={criticalCount > 0 ? `${criticalCount} critical needs attention` : undefined}
        />
        <StatCard
          label="Files scanned"
          value={scannerSummary.filesScanned}
          icon={FolderGit2}
          color="var(--color-primary)"
          status={`${scannerSummary.cleanFiles} clean · ${scannerSummary.affectedFiles} affected`}
        />
        <StatCard
          label="Scan duration"
          value={formatDuration(scannerSummary.duration)}
          icon={Clock3}
          color="var(--success)"
          status="All files processed"
        />
      </div>

      {/* Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <Section title="Findings by severity" subtitle="Understand where your risk is concentrated.">
          <SeverityFunnel severityData={severityData} />
          <p className="pt-1 text-[11px] text-[var(--muted)]">
            Sized by finding volume, not risk level · {findingsBySeverityTotal} total findings
          </p>
        </Section>

        <Section title="Findings by control" subtitle="Map violations to your CIS security baseline.">
          <ControlBreakdown controlData={controlData} total={totalControlFindings} />
        </Section>
      </div>

      {/* Findings table */}
      <div className="rounded-2xl border border-[var(--border)] bg-[var(--surface)] overflow-hidden" style={{ boxShadow: "var(--shadow-2)" }}>
        <div className="flex items-center justify-between px-5 py-4 border-b border-[var(--border)]">
          <div>
            <h2 className="text-sm font-semibold text-[var(--text)]">CIS findings</h2>
            <p className="text-xs text-[var(--muted)]">{filteredFindings.length} of {cisFindings.length} findings shown</p>
          </div>
        </div>
        <div style={{ padding: "16px 20px 8px", overflow: "visible" }}>
          <FilterBar
            selectedSeverities={selectedSeverities}
            selectedTypes={selectedTypes}
            typeOptions={typeOptions}
            selectedCategories={[]}
            categoryOptions={[]}
            toggleSeverity={toggleSeverity}
            toggleType={toggleType}
            toggleCategory={() => {}}
            selectAllSeverities={selectAllSeverities}
            clearAllSeverities={clearAllSeverities}
            selectAllTypes={selectAllTypes}
            clearAllTypes={clearAllTypes}
            selectAllCategories={() => {}}
            clearAllCategories={() => {}}
            selectedProviders={[]}
            providerOptions={[]}
            totalIssues={filteredFindings.length}
          />
        </div>
        <div style={{ padding: "0 20px 20px" }}>
          <FindingsTable
            findings={filteredFindings}
            totalFindings={cisFindings.length}
            repositoryContext={{
              installationId: selectedInstallation?.installationId || latestScan?.installation_id,
              repository: `${scanMetadata.organization || scanMetadata.org_name || ""}/${scanMetadata.repository || scanMetadata.repo_name || ""}`,
              branch: scanMetadata.branch || "main",
            }}
          />
        </div>
      </div>
    </div>
  );
}
