"use client";

import React from "react";
import { useScanStore } from "@/store/useScanStore";

// Modular Overview Components
import Section from "./metrics/Section";
import InfoCard from "./metrics/InfoCard";
import StatCard from "./metrics/StatCard";
import ScannerScores from "./scores/ScannerScores";
import EOLSection from "./maintenance/EOLSection";
import FindingList from "./findings/FindingList";
import ChartCard from "./common/ChartCard";
import EmptyState from "./common/EmptyState";
import TechStackIcon from "@/components/common/TechStackIcon";
import { OVERVIEW_DS } from "./designSystem";

// Utils
import { COLORS, formatDuration, formatApiText } from "./utils";

// Lucide Icons only for StatCard
import {
  Bug,
  ShieldCheck,
  FolderGit2,
  GitCommitHorizontal,
  UserRound,
  ScanSearch,
  GitBranch,
  Clock3,
} from "lucide-react";

const Overview = () => {
  const { latestScan } = useScanStore();

  if (!latestScan) return <EmptyState title="Scan Not Initiated" message="Start a new scan to find issues." />;

  const { scan_metadata, scan_results } = latestScan;
  const summary = scan_results?.scan_results?.summary;
  const scansFindings = scan_results?.scans_findings;

  // Robust EOL data extraction
  const sbomMetadata = scan_results?.scan_results?.scanner_results?.sbom?.metadata ||
    scan_results?.scan_results?.scanner_metadata?.sbom;
  const eolData = sbomMetadata?.eol ||
    scan_results?.scan_results?.summary?.eol ||
    scan_results?.scan_results?.eol ||
    scan_results?.eol ||
    null;
  const terraformProviders = sbomMetadata?.terraformProviders || null;
  // K8s deprecated API findings live in the kubernetes scanner metadata,
  // never in the IaC findings list (so they don't appear on the IaC page).
  const k8sDeprecated =
    scan_results?.scan_results?.scanner_results?.kubernetes?.metadata?.k8s_deprecated || null;

  const prepareScannerScores = () => {
    return summary?.score_summary || {};
  };

  const severitySummary = summary?.issues_summary?.total_issue_counts_by_severity || {};
  const issuesByScanner = summary?.issues_summary?.total_issues_by_subscan || {};

  const scannerScores = prepareScannerScores();
  const scanDuration = scan_results?.scan_results?.overall_duration || 0;
  const repositoryName = [scan_metadata?.organization, scan_metadata?.repository]
    .filter(Boolean)
    .join("/") || "Chinmaya0011/helmfile";
  const branchName = scan_metadata?.branch || "copilot/fix-1953";
  const commitMessage = String(scan_metadata?.commit_message ?? "").trim() || "N/A";
  const commitAuthor = String(scan_metadata?.commit_author ?? "").trim() || "N/A";
  const authorInitial = commitAuthor?.trim()?.charAt(0)?.toUpperCase() || "N";
  const durationValue = formatDuration(scanDuration);
  const repositoryOverviewCards = [
    {
      label: "Last Commit",
      value: commitMessage,
      icon: <GitCommitHorizontal />,
    },
    {
      label: "Commit Author",
      value: (
        <div className="inline-flex items-center gap-2 min-w-0">
          <span className="inline-flex h-6 w-6 items-center justify-center rounded-full bg-[color-mix(in_srgb,var(--color-primary)_14%,var(--surface))] text-xs font-semibold text-[var(--color-primary)]">
            {authorInitial}
          </span>
          <span className="truncate text-base font-semibold leading-tight text-[var(--text)]">
            {commitAuthor}
          </span>
        </div>
      ),
      icon: <UserRound />,
    },
    {
      label: "Scan Type",
      value: formatApiText(scan_metadata?.scan_type || "N/A"),
      icon: <ScanSearch />,
    },
    {
      label: "Event Type",
      value: formatApiText(scan_metadata?.event_type || "N/A"),
      icon: <GitBranch />,
    },
    {
      label: "Duration",
      value: (
        <div className="inline-flex items-center gap-2 min-w-0">
          <span className="inline-flex h-5 w-5 items-center justify-center rounded-md bg-[color-mix(in_srgb,var(--color-primary)_12%,var(--surface))] text-[var(--color-primary)] [&_svg]:h-3 [&_svg]:w-3">
            <Clock3 />
          </span>
          <span className="truncate text-base font-semibold leading-tight text-[var(--text)]">
            {durationValue}
          </span>
        </div>
      ),
      icon: <Clock3 />,
    },
  ];

  // 3 Primary Stats matching Figma design (Files Scanned, Total Issues, Status)
  const topStats = [
    {
      label: "Files Scanned",
      value: summary?.file_scanned || 0,
      icon: FolderGit2,
      color: COLORS.workflow || "var(--color-primary)",
    },
    {
      label: "Total Issues",
      value: summary?.issues_summary?.total_issues || 0,
      icon: Bug,
      color: COLORS.high || "var(--warning)",
    },
    {
      label: "Status",
      value: formatApiText(latestScan?.scan_status || "Completed"),
      icon: ShieldCheck,
      color: COLORS.success || "var(--success)",
    },
  ];

  return (
    <div className="relative overflow-x-hidden min-h-screen">
      <main className="relative z-[1] p-4 sm:p-6 flex flex-col gap-6 min-h-screen">
      {/* Repository Overview */}
      <Section>
        <div className="space-y-4">
          <div>
            <div className="flex flex-wrap items-center gap-3 text-sm md:text-base">
              <div className="flex items-center gap-2 whitespace-nowrap">
                <span className="inline-flex h-8 w-8 items-center justify-center rounded-lg bg-[color-mix(in_srgb,var(--color-primary)_14%,var(--surface))]">
                  <TechStackIcon name="github" size={18} />
                </span>
                <span
                  className="font-semibold text-[var(--text)]"
                  style={{ fontFamily: OVERVIEW_DS.typography.family, fontSize: OVERVIEW_DS.typography.body }}
                >
                  Repository Overview
                </span>
              </div>

              <span
                className="break-all font-semibold text-[var(--muted)]"
                style={{ fontFamily: OVERVIEW_DS.typography.family, fontSize: OVERVIEW_DS.typography.label }}
              >
                {repositoryName}
              </span>
              <span
                className="font-semibold text-[var(--muted)]"
                style={{ fontFamily: OVERVIEW_DS.typography.family, fontSize: OVERVIEW_DS.typography.micro }}
              >
                {branchName}
              </span>
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-5 gap-4 border-t border-[var(--border)] pt-4">
            {repositoryOverviewCards.map((card) => (
              <InfoCard
                key={card.label}
                label={card.label}
                value={card.value}
                icon={card.icon}
              />
            ))}
          </div>
        </div>
      </Section>

      {/* 3 Main Stat Cards (Files Scanned, Total Issues, Status) */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {topStats.map((stat, i) => (
          <div key={i}>
            <StatCard
              label={stat.label}
              value={stat.value}
              icon={stat.icon}
              color={stat.color}
            />
          </div>
        ))}
      </div>

      <div className="space-y-4">
        <div className="w-full h-full min-h-[250px]">
          <ScannerScores
            scoreSummary={scannerScores}
            severitySummary={severitySummary}
            issuesByScanner={issuesByScanner}
            scansFindings={scansFindings}
          />
        </div>
      </div>

      <EOLSection eolData={eolData} terraformProviders={terraformProviders} k8sDeprecated={k8sDeprecated} />

      {/* Charts + Findings */}
      <div className="space-y-4">
        <ChartCard
          title="Security Findings"
          description="Detailed issue compilation across environments and deployments"
          collapse={true}
          defaultExpanded={true}
          className="shadow-sm"
        >
          <div className="h-full min-h-[300px]">
            <FindingList
              scansFindings={scansFindings}
              scoreSummary={scannerScores}
            />
          </div>
        </ChartCard>
      </div>
      </main>
    </div>
  );
};

export default Overview;