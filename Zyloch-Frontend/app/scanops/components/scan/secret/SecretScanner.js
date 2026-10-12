"use client";

import React from "react";
import { useScanStore } from "@/store/useScanStore";
import LoadingState from "./LoadingState";
import ErrorState from "./ErrorState";
import EmptyState from "./EmptyState";
import SecretScannerHeader from "./SecretScannerHeader";
import ChartsSection from "./ChartsSection";
import FindingsList from "./FindingsList";
import AIScannerPopup from "@/app/scanops/components/scan/shared/AIScannerPopup";
import { formatApiText } from "@/app/scanops/components/scan/shared/textUtils";
import styles from "../workflow/Workflow.module.css";
import secretDetectionData from "@/data/secretDetection.json";

// Build lookup map once at module level (not inside render)
// API sends policy_code as "database_urls/postgres_url" or plain "github_token"
// infoTypes in JSON are the leaf key only: "postgres_url", "github_token"
const _byInfoType = {};
(secretDetectionData.detections ?? []).forEach((d) => {
  d.infoTypes?.forEach((t) => { _byInfoType[t] = d; });
});
const lookupDetection = (policyCode) => {
  if (!policyCode) return null;
  // Strip category prefix if present: "database_urls/postgres_url" → "postgres_url"
  const key = policyCode.includes("/")
    ? policyCode.split("/").pop()
    : policyCode;
  return _byInfoType[key] || null;
};

const SecretScanner = () => {
  const { latestScan, loading, error } = useScanStore();

  if (loading) return <LoadingState />;
  if (error) return <ErrorState error={error} />;

  if (!latestScan) {
    return <EmptyState title="Scan Not Initiated" message="Start a new scan to find issues." />;
  }

  if (!latestScan?.scan_results?.scans_findings?.["Secret_Scanner-findings"]?.length) {
    return <EmptyState message="No secret detection issues found in this scan." />;
  }

  const scanResults = latestScan.scan_results;
  const secretFindings = scanResults.scans_findings["Secret_Scanner-findings"];
  const summary = scanResults.scan_results?.summary;
  const scannerResults = scanResults.scan_results?.scanner_results?.secret_scanner;

  const scanMetadata = latestScan.scan_metadata;
  const securityScore =
    scannerResults?.metadata?.overall_score ||
    summary?.score_summary?.score_by_subscan?.secret_scanner ||
    0;

  const totalIssues = secretFindings.reduce(
    (total, f) => total + (f.violated_policies?.length || 0),
    0
  );

  const filesWithIssues = secretFindings.length;
  const filesScanned =
    scannerResults?.files_scanned ||
    summary?.file_scanned ||
    filesWithIssues;

  const severityBreakdown = { critical: 0, high: 0, medium: 0, low: 0 };

  (secretFindings || []).forEach((finding) => {
    (finding?.violated_policies || []).forEach((policy) => {
      const severity = String(policy?.severity || "medium").trim().toLowerCase();
      if (severityBreakdown.hasOwnProperty(severity)) {
        severityBreakdown[severity]++;
      } else {
        severityBreakdown.medium++;
      }
    });
  });

  const severityData = [
    { name: "Critical", value: severityBreakdown.critical, color: "var(--critical)" },
    { name: "High", value: severityBreakdown.high, color: "var(--high)" },
    { name: "Medium", value: severityBreakdown.medium, color: "var(--medium)" },
    { name: "Low", value: severityBreakdown.low, color: "var(--low)" }
  ].filter((item) => item.value > 0);

  const patternTypes = {};

  secretFindings.forEach((finding) => {
    finding.violated_policies?.forEach((policy) => {
      const policyName = policy.policy_name || "Unknown";

      let patternType = policyName;
      if (policyName.includes("/")) {
        patternType = policyName.split("/")[1] || policyName;
      }

      patternTypes[patternType] = (patternTypes[patternType] || 0) + 1;
    });
  });

  const patternTypesArray = Object.entries(patternTypes)
    .map(([name, count]) => ({
      name: formatApiText(name),
      count,
      percentage: ((count / totalIssues) * 100).toFixed(1),
    }))
    .sort((a, b) => b.count - a.count);

  const topPatternTypes = patternTypesArray.slice(0, 5);

  const pieChartData = Object.entries(patternTypes).map(([name, value]) => ({
    name: formatApiText(name),
    value,
    color: getColorFromName(name),
  }));

  const findingsData = secretFindings.flatMap((finding, fi) => {
    return (
      finding.violated_policies?.map((policy, pi) => {
        const redactedValue =
          policy.Matches || policy.description || "Hidden credential";

        // Match this policy against secretDetection.json via infoTypes key
        // policy_name = "database_urls/postgres_url" → strip prefix → "postgres_url"
        const matched = lookupDetection(policy.policy_name);

        return {
          id: `${finding.file_name}-${policy.policy_name}-${policy.Line_No}-${fi}-${pi}`,
          file_name: finding.file_name,
          line_no: policy.Line_No,
          severity: String(policy?.severity || matched?.severity || "medium").trim().toLowerCase(),
          // Use JSON title as pattern_type if matched, else fall back to API
          pattern_type: matched?.title || policy.policy_name || "Unknown",
          // Use JSON category if matched, else fall back to API description
          category: matched?.category || policy.description || "Unknown",
          // Use JSON finding field as description if matched
          description: matched?.finding || policy.description,
          // Wire up remediation from JSON recommendation
          remediation: matched?.recommendation || null,
          redacted_value: redactedValue,
          policy_code: policy.policy_code,
          policy_name: policy.policy_name,
        };
      }) || []
    );
  });

  const scanDuration = scannerResults?.duration || 0;

  const secretFiles = [...new Set(secretFindings.map((f) => f.file_name).filter(Boolean))];

  return (
    <div className={styles.pageRoot}>
      <main className={styles.contentWrap}>
        <AIScannerPopup files={secretFiles} />
        <SecretScannerHeader
          scanMetadata={scanMetadata}
          securityScore={securityScore}
          scannerResults={scannerResults}
          scanDuration={scanDuration}
        />

        <ChartsSection
          severityData={severityData}
          pieChartData={pieChartData}
          securityScore={securityScore}
        />

        <FindingsList
          findings={findingsData}
          totalIssues={totalIssues}
          filesWithIssues={filesWithIssues}
        />
      </main>
    </div>
  );
};

// Utility
const getColorFromName = (name) => {
  let hash = 0;
  for (let i = 0; i < name.length; i++) {
    hash = name.charCodeAt(i) + ((hash << 5) - hash);
  }

  const colors = [
    "var(--critical)", "var(--high)", "var(--medium)", "var(--low)",
    "#ef4444", "#f97316", "#f59e0b", "#22c55e",
    "#06b6d4", "#3b82f6", "#8b5cf6"
  ];

  return colors[Math.abs(hash) % colors.length];
};

export default SecretScanner;