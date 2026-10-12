const SCANNER_KEYS = ["cis-agent", "cis_agent"];
const FINDINGS_KEYS = ["Cis-Agent-findings", "cis-agent-findings", "Cis-agent-findings"];

const firstValue = (...values) => values.find((value) => value !== undefined && value !== null);

const getCisResult = (latestScan) => {
  const root = latestScan || {};
  const response = root.scan_results || {};
  const nestedResults = response.scan_results || response;
  const scannerResults = nestedResults.scanner_results || response.scanner_results || root.scanner_results || {};

  return firstValue(
    ...SCANNER_KEYS.map((key) => scannerResults[key]),
    ...SCANNER_KEYS.map((key) => response[key]),
  ) || {};
};

const getFindingFiles = (latestScan) => {
  const root = latestScan || {};
  const response = root.scan_results || {};
  const nestedResults = response.scan_results || response;
  const findings = nestedResults.scans_findings || response.scans_findings || root.scans_findings || {};
  return firstValue(...FINDINGS_KEYS.map((key) => findings[key])) || [];
};

const normalizeFinding = (finding, index) => {
  const file = firstValue(finding.file, finding.file_name, finding.path, "Unknown file");
  const policyCode = firstValue(finding.policy_code, "CIS-UNKNOWN");
  const severity = String(firstValue(finding.severity, "medium")).toLowerCase();

  return {
    ...finding,
    id: firstValue(finding.id, `${policyCode}-${file}-${index}`),
    policyCode,
    policyName: firstValue(finding.policy_name, "CIS control violation"),
    title: firstValue(finding.description, finding.policy_name, "CIS control violation"),
    description: firstValue(finding.description, "No description provided"),
    severity: ["critical", "high", "medium", "low"].includes(severity) ? severity : "medium",
    type: policyCode,
    scannerType: "cis-agent",
    provider: null,
    category: policyCode,
    file,
    fullPath: file,
    lineNo: firstValue(finding.Line_No, finding.line_no, finding.line, "-"),
    matches: firstValue(finding.Matches, finding.matches),
    codeBlock: finding.code_block,
    remediation: firstValue(finding.remediation, finding.recommendation),
    references: firstValue(finding.reference, finding.references),
  };
};

export const processCisScanData = (latestScan) => {
  if (!latestScan) return null;

  const cisResult = getCisResult(latestScan);
  const metadata = cisResult.metadata || {};
  const findingFiles = getFindingFiles(latestScan);

  const cisFindings = findingFiles.flatMap((fileFinding) => (
    (fileFinding?.violated_policies || []).map((finding, idx) => normalizeFinding({
      ...finding,
      file_name: fileFinding.file_name,
    }, `${fileFinding.file_name}-${idx}`))
  ));

  const bySeverity = ["critical", "high", "medium", "low"].reduce((result, severity) => {
    result[severity] = cisFindings.filter((finding) => finding.severity === severity).length;
    return result;
  }, {});

  const severityBreakdown = metadata.severity_breakdown || {};
  const controlBreakdown = metadata.control_breakdown || {};

  const typeOptions = Array.from(new Set(cisFindings.map((finding) => finding.type))).sort().map((id) => ({
    id,
    label: id,
  }));
  const categoryOptions = typeOptions;

  const controlData = Object.entries(controlBreakdown)
    .map(([control, count]) => ({ control, count: Number(count) || 0 }))
    .sort((a, b) => b.count - a.count);
  const totalControlFindings = controlData.reduce((sum, item) => sum + item.count, 0);

  const findingsCount = firstValue(cisResult.findings_count, metadata.total_findings, cisFindings.length, 0);
  const filesScanned = firstValue(cisResult.files_scanned, metadata.total_files, findingFiles.length, 0);
  const affectedFiles = new Set(cisFindings.map((finding) => finding.fullPath)).size;
  const cleanFiles = Math.max(0, filesScanned - affectedFiles);

  return {
    cisResult,
    cisMetadata: metadata,
    cisFindings,
    typeOptions,
    categoryOptions,
    controlData,
    totalControlFindings,
    scannerSummary: {
      filesScanned,
      affectedFiles,
      cleanFiles,
      findingsCount,
      duration: firstValue(cisResult.duration, 0),
      overallScore: firstValue(metadata.overall_score, 0),
      framework: firstValue(metadata.framework, "CIS Controls v8.1 AI Agents Companion Guide"),
      reference: metadata.reference,
      severityBreakdown: ["critical", "high", "medium", "low"].reduce((result, severity) => {
        result[severity] = firstValue(severityBreakdown[severity], bySeverity[severity], 0);
        return result;
      }, {}),
    },
    severityData: [
      { name: "Critical", value: firstValue(severityBreakdown.critical, bySeverity.critical, 0), color: "var(--critical)" },
      { name: "High", value: firstValue(severityBreakdown.high, bySeverity.high, 0), color: "var(--high)" },
      { name: "Medium", value: firstValue(severityBreakdown.medium, bySeverity.medium, 0), color: "var(--medium)" },
      { name: "Low", value: firstValue(severityBreakdown.low, bySeverity.low, 0), color: "var(--low)" },
    ],
    scanMetadata: latestScan.scan_metadata || {},
  };
};
