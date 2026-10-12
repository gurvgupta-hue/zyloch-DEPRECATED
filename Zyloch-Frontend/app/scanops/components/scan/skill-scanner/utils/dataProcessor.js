const SCANNER_KEYS = ["skill-scanner", "skill_scanner"];

const firstValue = (...values) => values.find((value) => value !== undefined && value !== null);

const asArray = (value) => {
  if (Array.isArray(value)) return value;
  if (!value || typeof value !== "object") return [];
  return Object.values(value).flatMap((item) => (Array.isArray(item) ? item : [item]));
};

const getSkillResult = (latestScan) => {
  const root = latestScan || {};
  const response = root.scan_results || {};
  const nestedResults = response.scan_results || response;
  const scannerResults = nestedResults.scanner_results || response.scanner_results || root.scanner_results || {};

  return firstValue(
    ...SCANNER_KEYS.map((key) => scannerResults[key]),
    ...SCANNER_KEYS.map((key) => response[key]),
  ) || {};
};

const getFindings = (latestScan) => {
  const root = latestScan || {};
  const response = root.scan_results || {};
  const nestedResults = response.scan_results || response;
  const findings = nestedResults.scans_findings || response.scans_findings || root.scans_findings || {};
  return findings["Skill-Scanner-findings"] || findings["skill-scanner-findings"] || [];
};

const normalizeFinding = (finding, index) => {
  const file = firstValue(finding.file, finding.file_name, finding.path, finding.location?.file, "Unknown file");
  const type = String(firstValue(finding.type, finding.finding_type, finding.category, "skill")).toLowerCase();
  const severity = String(firstValue(finding.severity, finding.risk_level, "medium")).toLowerCase();

  return {
    ...finding,
    id: firstValue(finding.id, finding.finding_id, `${type}-${file}-${index}`),
    policyCode: firstValue(finding.policy_code, finding.code, finding.owasp_id, finding.asi_id, finding.type, "SKILL-UNKNOWN"),
    policyName: firstValue(finding.policy_name, finding.title, finding.name, "AI security finding"),
    title: firstValue(finding.title, finding.policy_name, finding.name, finding.description, "AI security finding"),
    description: firstValue(finding.description, finding.detail, finding.message, "No description provided"),
    severity: ["critical", "high", "medium", "low"].includes(severity) ? severity : "medium",
    type,
    scannerType: "skill-scanner",
    provider: firstValue(finding.provider, finding.source, null),
    category: firstValue(finding.category, finding.framework, "AI security"),
    file,
    fullPath: file,
    lineNo: firstValue(finding.line, finding.line_number, finding.line_no, finding.Line_No, finding.location?.line, "-"),
    matches: firstValue(finding.matches, finding.Matches),
    codeBlock: finding.code_block,
    remediation: firstValue(finding.remediation, finding.recommendation, finding.fix),
    references: firstValue(finding.references, finding.reference),
  };
};

export const processScanData = (latestScan) => {
  if (!latestScan) return null;

  const skillResult = getSkillResult(latestScan);
  const chartMetadata = skillResult.metadata || skillResult;
  const findingFiles = getFindings(latestScan);
  const skillFindings = findingFiles.flatMap((fileFinding) => (
    (fileFinding?.violated_policies || []).map((finding) => normalizeFinding({
      ...finding,
      file_name: fileFinding.file_name,
    }, fileFinding.file_name))
  ));
  const bySeverity = ["critical", "high", "medium", "low"].reduce((result, severity) => {
    result[severity] = skillFindings.filter((finding) => finding.severity === severity).length;
    return result;
  }, {});
  const typeCounts = skillFindings.reduce((result, finding) => {
    result[finding.type] = (result[finding.type] || 0) + 1;
    return result;
  }, {});
  const typeOptions = Object.keys(typeCounts).sort().map((id) => ({
    id,
    label: id.replace(/[-_]+/g, " ").replace(/\b\w/g, (letter) => letter.toUpperCase()),
  }));
  const categoryCounts = skillFindings.reduce((result, finding) => {
    const category = String(finding.category || "uncategorized");
    result[category] = (result[category] || 0) + 1;
    return result;
  }, {});
  const categoryOptions = Object.keys(categoryCounts).sort().map((id) => ({
    id,
    label: id.replace(/[-_]+/g, " ").replace(/\b\w/g, (letter) => letter.toUpperCase()),
  }));
  const severityBreakdown = chartMetadata.severity_breakdown || {};
  const scannerSummary = {
    filesScanned: firstValue(skillResult.files_scanned, chartMetadata.total_skill_files, findingFiles.length, 0),
    findingsCount: firstValue(skillResult.findings_count, chartMetadata.total_findings, skillFindings.length, 0),
    severityBreakdown: ["critical", "high", "medium", "low"].reduce((result, severity) => {
      result[severity] = firstValue(severityBreakdown[severity], bySeverity[severity], 0);
      return result;
    }, {}),
  };

  return {
    ...latestScan,
    skillResult,
    skillFindings,
    typeOptions,
    typeCounts,
    categoryOptions,
    categoryCounts,
    scannerSummary,
    skillSummary: {
      totalIssues: skillFindings.length,
      totalFiles: new Set(skillFindings.map((finding) => finding.fullPath)).size,
      bySeverity,
    },
    severityData: [
      { name: "Critical", value: bySeverity.critical, color: "var(--critical)" },
      { name: "High", value: bySeverity.high, color: "var(--high)" },
      { name: "Medium", value: bySeverity.medium, color: "var(--medium)" },
      { name: "Low", value: bySeverity.low, color: "var(--low)" },
    ].filter((item) => item.value > 0),
    issuesByTypeData: typeOptions.map((type, index) => ({
      name: type.label,
      issues: typeCounts[type.id],
      color: ["#06B6D4", "#F97316", "#22C55E", "#EAB308", "#FB7185"][index % 5],
    })),
    frameworkMappings: {
      issueByScanner: chartMetadata.issue_by_scanner || {},
      euAiAct: chartMetadata.eu_ai_act_mapping || {},
      nist: chartMetadata.nist_ai_rmf_mapping || {},
      mitre: chartMetadata.mitre_atlas_mapping || {},
      owasp: chartMetadata.owasp_mapping || [],
    },
    filesScanned: scannerSummary.filesScanned,
    scanMetadata: latestScan.scan_metadata || {},
  };
};
