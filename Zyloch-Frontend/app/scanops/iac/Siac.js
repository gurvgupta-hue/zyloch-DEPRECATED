// components/iac-scan-dashboard.jsx
'use client';

import React, { useRef, useState, useMemo, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { useScanStore } from "@/store/useScanStore";
import { useInteractiveTable } from "../components/scan/shared/useInteractiveTable";

// CHART COMPONENTS
import BarChartUI from "@/components/charts/BarChartUI";
import PieChartUI from "@/components/charts/PieChartUI";

// SMART TRUNCATE
import SmartTruncate from "@/components/ui/SmartTruncate";

// ICONS
import {
  FileText,
  AlertTriangle,
  AlertCircle,
  CheckCircle2,
  Shield,
  GitBranch,
  Calendar,
  User,
  ExternalLink,
  ChevronDown,
  ChevronUp,
  Box,
  Layers,
  Cloud,
  FileCode,
  FileText,
  Skull,
  Flame,
  Zap,
  Info,
  Filter,
  X,
  ShieldAlert,
} from "lucide-react";

// SEVERITY VISUALS
import {
  getSeverityIcon,
  getSeverityColorToken,
  getFigmaSeverityBadgeStyle,
  TableSeverityBadge,
} from "@/app/scanops/components/scan/shared/severityVisuals";

// ==================================================================
// IAC DASHBOARD PAGE
// ==================================================================

const IaCDashboard = ({ scanId }) => {
  const { latestScan, loading, error } = useScanStore();
  const [selectedTypes, setSelectedTypes] = useState(["docker", "kubernetes", "terraform", "bicep", "arm"]);
  const [selectedSeverities, setSelectedSeverities] = useState(["critical", "high", "medium", "low"]);
  const [searchTerm, setSearchTerm] = useState("");
  const [activeTab, setActiveTab] = useState("all");

  // Dropdown states
  const [typeDropdownOpen, setTypeDropdownOpen] = useState(false);
  const [severityDropdownOpen, setSeverityDropdownOpen] = useState(false);
  const tableRef = useRef(null);

  // Process scan data for the dashboard
  const processedData = useMemo(() => {
    if (!latestScan) return null;



    const scanResults = latestScan.scan_results;
    const summary = scanResults?.scan_results?.summary;
    const findings = scanResults?.scans_findings || {};
    const scannerResults = scanResults?.scan_results?.scanner_results || {};

    // Process Docker findings
    const dockerFindings = (findings["Docker-findings"] || []).flatMap(fileFindings => {
      return (fileFindings.violated_policies || []).map(policy => ({
        id: `${policy.policy_code}-${fileFindings.file_name}`,
        policyCode: policy.policy_code || "DOCKER-UNKNOWN",
        policyName: policy.policy_name || "docker_policy",
        severity: policy.severity?.toLowerCase() || "medium",
        type: "docker",
        provider: "docker",
        title: policy.description || "Docker security issue",
        description: policy.description || "No description provided",
        file: fileFindings.file_name.split("/").pop() || "Dockerfile",
        fullPath: fileFindings.file_name,
        lineNo: policy.Line_No || "-",
        matches: policy.Matches,
        remediation: policy.remediation,
      }));
    });

    // Process Kubernetes findings
    const kubernetesFindings = (findings["Kubernetes-findings"] || []).flatMap(fileFindings =>
      (fileFindings.violated_policies || []).map(policy => ({
        id: `${policy.policy_code}-${fileFindings.file_name}`,
        policyCode: policy.policy_code || "K8S-UNKNOWN",
        policyName: policy.policy_name || "kubernetes_policy",
        severity: policy.severity?.toLowerCase() || "medium",
        type: "kubernetes",
        provider: "kubernetes",
        title: policy.description || "Kubernetes security issue",
        description: policy.description || "No description provided",
        file: fileFindings.file_name.split("/").pop() || "manifest.yaml",
        fullPath: fileFindings.file_name,
        lineNo: policy.Line_No || "-",
        matches: policy.Matches,
        remediation: policy.remediation,
      }))
    );

    // Process ALL Terraform findings (AWS, Azure, GCP) and combine them
    const terraformAwsFindings = (findings["Terraform_Aws-findings"] || []).flatMap(fileFindings =>
      (fileFindings.violated_policies || []).map(policy => ({
        id: `${policy.policy_code}-${fileFindings.file_name}`,
        policyCode: policy.policy_code || "TF-AWS-UNKNOWN",
        policyName: policy.policy_name || "terraform_aws_policy",
        severity: policy.severity?.toLowerCase() || "medium",
        type: "terraform",
        provider: "aws",
        title: policy.description || "Terraform AWS security issue",
        description: policy.description || "No description provided",
        file: fileFindings.file_name.split("/").pop() || "main.tf",
        fullPath: fileFindings.file_name,
        lineNo: policy.Line_No || "-",
        matches: policy.Matches,
        remediation: policy.remediation,
      }))
    );

    const terraformAzureFindings = (findings["Terraform_Azure-findings"] || []).flatMap(fileFindings =>
      (fileFindings.violated_policies || []).map(policy => ({
        id: `${policy.policy_code}-${fileFindings.file_name}`,
        policyCode: policy.policy_code || "TF-AZURE-UNKNOWN",
        policyName: policy.policy_name || "terraform_azure_policy",
        severity: policy.severity?.toLowerCase() || "medium",
        type: "terraform",
        provider: "azure",
        title: policy.description || "Terraform Azure security issue",
        description: policy.description || "No description provided",
        file: fileFindings.file_name.split("/").pop() || "main.tf",
        fullPath: fileFindings.file_name,
        lineNo: policy.Line_No || "-",
        matches: policy.Matches,
        remediation: policy.remediation,
      }))
    );

    const terraformGcpFindings = (findings["Terraform_Gcp-findings"] || []).flatMap(fileFindings =>
      (fileFindings.violated_policies || []).map(policy => ({
        id: `${policy.policy_code}-${fileFindings.file_name}`,
        policyCode: policy.policy_code || "TF-GCP-UNKNOWN",
        policyName: policy.policy_name || "terraform_gcp_policy",
        severity: policy.severity?.toLowerCase() || "medium",
        type: "terraform",
        provider: "gcp",
        title: policy.description || "Terraform GCP security issue",
        description: policy.description || "No description provided",
        file: fileFindings.file_name.split("/").pop() || "main.tf",
        fullPath: fileFindings.file_name,
        lineNo: policy.Line_No || "-",
        matches: policy.Matches,
        remediation: policy.remediation,
      }))
    );

    // Combine all Terraform findings
    const terraformFindings = [
      ...terraformAwsFindings,
      ...terraformAzureFindings,
      ...terraformGcpFindings
    ];

    // Process Bicep and ARM findings (both come through the "Bicep-findings" key;
    // native .bicep files and ARM template .json files are distinguished by extension)
    const bicepFindings = [];
    const armFindings = [];

    (findings["Bicep-findings"] || []).forEach(fileFindings => {
      const isArm = fileFindings.file_name.endsWith(".json");
      (fileFindings.violated_policies || []).forEach(policy => {
        const finding = {
          id: `${policy.policy_code}-${fileFindings.file_name}`,
          policyCode: policy.policy_code || (isArm ? "ARM-UNKNOWN" : "BICEP-UNKNOWN"),
          policyName: policy.policy_name || "psrule_azure",
          severity: policy.severity?.toLowerCase() || "medium",
          type: isArm ? "arm" : "bicep",
          provider: "azure",
          title: policy.description || (isArm ? "ARM template security issue" : "Bicep Azure security issue"),
          description: policy.description || "No description provided",
          file: fileFindings.file_name.split("/").pop() || (isArm ? "template.json" : "main.bicep"),
          fullPath: fileFindings.file_name,
          lineNo: policy.Line_No || "-",
          matches: policy.Matches,
          remediation: policy.remediation,
        };
        if (isArm) armFindings.push(finding);
        else bicepFindings.push(finding);
      });
    });

    const allFindings = [
      ...dockerFindings,
      ...kubernetesFindings,
      ...terraformFindings,
      ...bicepFindings,
      ...armFindings,
    ];



    // Calculate IaC-specific summary
    const iacSummary = {
      totalIssues: allFindings.length,
      totalFiles: new Set(allFindings.map(f => f.fullPath)).size,
      bySeverity: {
        critical: allFindings.filter(f => f.severity === "critical").length,
        high: allFindings.filter(f => f.severity === "high").length,
        medium: allFindings.filter(f => f.severity === "medium").length,
        low: allFindings.filter(f => f.severity === "low").length,
      },
      byType: {
        docker: {
          issues: dockerFindings.length,
          files: new Set(dockerFindings.map(f => f.fullPath)).size,
          filesScanned: scannerResults?.docker?.files_scanned || 0,
        },
        kubernetes: {
          issues: kubernetesFindings.length,
          files: new Set(kubernetesFindings.map(f => f.fullPath)).size,
          filesScanned: scannerResults?.kubernetes?.files_scanned || 0,
        },
        terraform: {
          issues: terraformFindings.length,
          files: new Set(terraformFindings.map(f => f.fullPath)).size,
          filesScanned: (scannerResults?.terraform_aws?.files_scanned || 0) +
            (scannerResults?.terraform_azure?.files_scanned || 0) +
            (scannerResults?.terraform_gcp?.files_scanned || 0),
          providers: {
            aws: terraformAwsFindings.length,
            azure: terraformAzureFindings.length,
            gcp: terraformGcpFindings.length,
          }
        },
        bicep: {
          issues: bicepFindings.length,
          files: new Set(bicepFindings.map(f => f.fullPath)).size,
          filesScanned: scannerResults?.bicep?.files_scanned || 0,
        },
        arm: {
          issues: armFindings.length,
          files: new Set(armFindings.map(f => f.fullPath)).size,
          filesScanned: scannerResults?.bicep?.total_arm_files || new Set(armFindings.map(f => f.fullPath)).size,
        },
      },
    };

    return {
      ...latestScan,
      iacFindings: allFindings,
      dockerFindings,
      kubernetesFindings,
      terraformFindings,
      terraformAwsFindings,
      terraformAzureFindings,
      terraformGcpFindings,
      bicepFindings,
      armFindings,
      iacSummary,
      summary,
      scannerResults,
      scanMetadata: latestScan.scan_metadata,
    };
  }, [latestScan]);

  // Filter findings based on selected filters and active tab
  const filteredFindings = useMemo(() => {
    if (!processedData?.iacFindings) return [];

    return processedData.iacFindings.filter((finding) => {
      // Tab filter
      if (activeTab !== "all" && finding.severity !== activeTab) {
        return false;
      }

      const matchesSeverity = selectedSeverities.includes(finding.severity);
      const matchesType = selectedTypes.includes(finding.type);
      const matchesSearch =
        searchTerm === "" ||
        finding.title?.toLowerCase().includes(searchTerm.toLowerCase()) ||
        finding.file?.toLowerCase().includes(searchTerm.toLowerCase()) ||
        finding.id?.toLowerCase().includes(searchTerm.toLowerCase()) ||
        finding.policyCode?.toLowerCase().includes(searchTerm.toLowerCase());

      return matchesSeverity && matchesType && matchesSearch;
    });
  }, [processedData, selectedSeverities, selectedTypes, searchTerm, activeTab]);

  useInteractiveTable({
    containerRef: tableRef,
    storageKey: "scanops-iac-dashboard-table",
    minWidth: 84,
    deps: [filteredFindings.length, selectedSeverities.join("|"), selectedTypes.join("|"), searchTerm, activeTab],
  });

  // Prepare chart data
  const severityData = useMemo(() => {
    if (!processedData?.iacSummary) return [];

    return [
      { name: "Critical", value: processedData.iacSummary.bySeverity.critical, color: "var(--critical)" },
      { name: "High", value: processedData.iacSummary.bySeverity.high, color: "var(--high)" },
      { name: "Medium", value: processedData.iacSummary.bySeverity.medium, color: "var(--medium)" },
      { name: "Low", value: processedData.iacSummary.bySeverity.low, color: "var(--low)" },
    ].filter(item => item.value > 0);
  }, [processedData]);

  const issuesByTypeData = useMemo(() => {
    if (!processedData?.iacSummary) return [];

    return [
      {
        name: "Docker",
        issues: processedData.iacSummary.byType.docker.issues,
        files: processedData.iacSummary.byType.docker.files,
        filesScanned: processedData.iacSummary.byType.docker.filesScanned,
        color: "var(--chart-cyan)",
      },
      {
        name: "Kubernetes",
        issues: processedData.iacSummary.byType.kubernetes.issues,
        files: processedData.iacSummary.byType.kubernetes.files,
        filesScanned: processedData.iacSummary.byType.kubernetes.filesScanned,
        color: "var(--chart-low)",
      },
      {
        name: "Terraform",
        issues: processedData.iacSummary.byType.terraform.issues,
        files: processedData.iacSummary.byType.terraform.files,
        filesScanned: processedData.iacSummary.byType.terraform.filesScanned,
        color: "var(--chart-medium)",
      },
      {
        name: "Bicep",
        issues: processedData.iacSummary.byType.bicep.issues,
        files: processedData.iacSummary.byType.bicep.files,
        filesScanned: processedData.iacSummary.byType.bicep.filesScanned,
        color: "var(--chart-blue)",
      },
    ].filter(item => item.issues > 0);
  }, [processedData]);

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
    setSelectedTypes(["docker", "kubernetes", "terraform", "bicep", "arm"]);
  };

  const clearAllTypes = () => {
    setSelectedTypes([]);
  };

  // Close dropdowns when clicking outside
  useEffect(() => {
    const handleClickOutside = (event) => {
      if (!event.target.closest('.type-dropdown') && !event.target.closest('.severity-dropdown')) {
        setTypeDropdownOpen(false);
        setSeverityDropdownOpen(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  if (loading) return <LoadingState />;
  if (error) return <ErrorState error={error} />;

  // Check if we have processedData
  if (!processedData) {
    return <EmptyState title="Scan Not Initiated" message="Start a new scan to find issues." />;
  }

  // Check if there are any findings at all
  if (processedData.iacFindings.length === 0) {
    return <EmptyState message="No infrastructure as code security issues detected in this scan." />;
  }

  const { scanMetadata, iacSummary, scannerResults } = processedData;
  const securityScore = processedData.summary?.score_summary?.overall_score || 0;

  return (
    <div className="relative overflow-x-hidden min-h-screen">
      {/* Decorative background elements using root variables */}
      <div className="fixed inset-0 pointer-events-none overflow-hidden">
        <div className="absolute top-0 right-0 w-96 h-96 bg-gradient-to-br from-primary/5 to-transparent rounded-full blur-3xl"></div>
        <div className="absolute bottom-0 left-0 w-96 h-96 bg-gradient-to-tr from-secondary/5 to-transparent rounded-full blur-3xl"></div>
      </div>

      <main className="relative z-10 p-4 sm:p-6 flex flex-col gap-6 min-h-screen">
        {/* Scan Status Summary */}
        {/* <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
          <StatusCard
            label="Docker"
            status={scannerResults?.docker?.status}
            filesScanned={scannerResults?.docker?.files_scanned}
            findings={processedData.dockerFindings.length}
          />
          <StatusCard
            label="Kubernetes"
            status={scannerResults?.kubernetes?.status}
            filesScanned={scannerResults?.kubernetes?.files_scanned}
            findings={processedData.kubernetesFindings.length}
          />
          <StatusCard
            label="Terraform"
            status="completed"
            filesScanned={(scannerResults?.terraform_aws?.files_scanned || 0) + 
                         (scannerResults?.terraform_azure?.files_scanned || 0) + 
                         (scannerResults?.terraform_gcp?.files_scanned || 0)}
            findings={processedData.terraformFindings.length}
          />
        </div> */}

        {/* Terraform Provider Breakdown */}
        {processedData.terraformFindings.length > 0 && (
          <div className="grid grid-cols-3 gap-4 mb-4">
            <ProviderCard
              provider="AWS"
              count={processedData.terraformAwsFindings.length}
              color="var(--chart-orange)"
            />
            <ProviderCard
              provider="Azure"
              count={processedData.terraformAzureFindings.length}
              color="var(--chart-blue)"
            />
            <ProviderCard
              provider="GCP"
              count={processedData.terraformGcpFindings.length}
              color="var(--chart-green)"
            />
          </div>
        )}

        {processedData.bicepFindings.length > 0 && (
          <div className="grid grid-cols-1 gap-4 mb-4">
            <ProviderCard
              provider="Bicep (Azure)"
              count={processedData.bicepFindings.length}
              color="var(--chart-blue)"
            />
          </div>
        )}

        {/* SUMMARY CARDS - Separated High/Critical */}
        <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
          <SummaryCard
            label="Total Issues"
            value={iacSummary.totalIssues}
            icon={AlertTriangle}
            color="var(--color-primary)"
          />
          <SummaryCard
            label="Critical"
            value={iacSummary.bySeverity.critical}
            icon={Skull}
            color="var(--critical)"
          />
          <SummaryCard
            label="High"
            value={iacSummary.bySeverity.high}
            icon={Flame}
            color="var(--high)"
          />
          <SummaryCard
            label="Medium"
            value={iacSummary.bySeverity.medium}
            icon={Zap}
            color="var(--medium)"
          />
          <SummaryCard
            label="Low"
            value={iacSummary.bySeverity.low}
            icon={Info}
            color="var(--low)"
          />
        </div>

        {/* CHARTS SECTION */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Severity Distribution - Pie Chart */}
          <div className="bg-surface rounded-2xl shadow-2 p-6 border border-default hover-lift transition-normal">
            <div className="mb-4">
              <h3 className="text-lg font-semibold text">Severity Distribution</h3>
              <p className="text-xs text-muted mt-1">Risk prioritization and severity tiers</p>
            </div>
            {severityData.length > 0 ? (
              <PieChartUI data={severityData} />
            ) : (
              <div className="h-64 flex items-center justify-center text-muted">
                No severity data available
              </div>
            )}
          </div>

          {/* Issues by IaC Type - Bar Chart */}
          <div className="bg-surface rounded-2xl shadow-2 p-6 border border-default hover-lift transition-normal">
            <div className="mb-4">
              <h3 className="text-lg font-semibold text">Issues by IaC Type</h3>
              <p className="text-xs text-muted mt-1">Distribution across Docker, K8s, and Terraform</p>
            </div>
            <BarChartUI
              data={issuesByTypeData.map(item => ({
                name: item.name,
                value: item.issues,
                color: item.color,
              }))}
            />
            <div className="flex flex-wrap justify-center gap-4 mt-4 text-xs text-muted">
              <span>Docker: {issuesByTypeData.find(d => d.name === "Docker")?.issues || 0}</span>
              <span>K8s: {issuesByTypeData.find(d => d.name === "Kubernetes")?.issues || 0}</span>
              <span>Terraform: {issuesByTypeData.find(d => d.name === "Terraform")?.issues || 0}</span>
              <span>Bicep: {issuesByTypeData.find(d => d.name === "Bicep")?.issues || 0}</span>
            </div>
          </div>
        </div>

        {/* FILTERS AND TABLE SECTION */}
        <div className="bg-surface rounded-2xl shadow-2 p-6 border border-default">
          {/* Severity Tabs */}
          <div className="flex gap-2 mb-6 border-b border-default pb-4 overflow-x-auto">
            <button
              onClick={() => setActiveTab("all")}
              className={`px-4 py-2 rounded-md text-sm font-medium transition-fast whitespace-nowrap ${activeTab === "all"
                ? "bg-primary text-on-primary"
                : "text-muted hover:text-text"
                }`}
            >
              All Issues ({iacSummary.totalIssues})
            </button>
            <button
              onClick={() => setActiveTab("critical")}
              className={`px-4 py-2 rounded-md text-sm font-medium transition-fast flex items-center gap-1 whitespace-nowrap ${activeTab === "critical"
                ? "bg-critical text-on-primary"
                : "text-muted hover:text-text"
                }`}
            >
              <Skull className="w-4 h-4" />
              Critical ({iacSummary.bySeverity.critical})
            </button>
            <button
              onClick={() => setActiveTab("high")}
              className={`px-4 py-2 rounded-md text-sm font-medium transition-fast flex items-center gap-1 whitespace-nowrap ${activeTab === "high"
                ? "bg-high text-on-primary"
                : "text-muted hover:text-text"
                }`}
            >
              <Flame className="w-4 h-4" />
              High ({iacSummary.bySeverity.high})
            </button>
            <button
              onClick={() => setActiveTab("medium")}
              className={`px-4 py-2 rounded-md text-sm font-medium transition-fast flex items-center gap-1 whitespace-nowrap ${activeTab === "medium"
                ? "bg-medium text-on-primary"
                : "text-muted hover:text-text"
                }`}
            >
              <Zap className="w-4 h-4" />
              Medium ({iacSummary.bySeverity.medium})
            </button>
            <button
              onClick={() => setActiveTab("low")}
              className={`px-4 py-2 rounded-md text-sm font-medium transition-fast flex items-center gap-1 whitespace-nowrap ${activeTab === "low"
                ? "bg-low text-on-primary"
                : "text-muted hover:text-text"
                }`}
            >
              <Info className="w-4 h-4" />
              Low ({iacSummary.bySeverity.low})
            </button>
          </div>

          <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4 mb-6">
            <h3 className="text-xl font-semibold text">Security Findings</h3>

            <div className="flex flex-wrap gap-3">
              {/* Search */}
              <div className="relative">
                <input
                  type="text"
                  placeholder="Search findings..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="pl-10 pr-4 py-2 bg-elevated border border-default rounded-md focus-ring text-sm w-64"
                />
                <svg
                  className="absolute left-3 top-2.5 h-4 w-4 text-muted"
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                >
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                </svg>
              </div>

              {/* Severity Filter Dropdown */}
              <div className="relative severity-dropdown">
                <button
                  onClick={() => {
                    setSeverityDropdownOpen(!severityDropdownOpen);
                    setTypeDropdownOpen(false);
                  }}
                  className={`px-3 py-2 rounded-md text-sm font-medium transition-fast flex items-center gap-2 border ${selectedSeverities.length > 0 && selectedSeverities.length < 4
                    ? "bg-primary/10 border-primary/30 text-primary"
                    : selectedSeverities.length === 4
                      ? "bg-elevated border-default text-muted"
                      : "bg-elevated border-default text-muted"
                    }`}
                >
                  <Filter className="w-4 h-4" />
                  <span>
                    Severity {selectedSeverities.length > 0 && selectedSeverities.length < 4
                      ? `(${selectedSeverities.length})`
                      : selectedSeverities.length === 4
                        ? "(All)"
                        : "(0)"}
                  </span>
                  <ChevronDown className={`w-4 h-4 transition-transform ${severityDropdownOpen ? 'rotate-180' : ''}`} />
                </button>

                <AnimatePresence>
                  {severityDropdownOpen && (
                    <motion.div
                      initial={{ opacity: 0, y: -10 }}
                      animate={{ opacity: 1, y: 0 }}
                      exit={{ opacity: 0, y: -10 }}
                      transition={{ duration: 0.2 }}
                      className="absolute right-0 mt-2 w-48 bg-surface border border-default rounded-lg shadow-3 z-50 overflow-hidden"
                    >
                      <div className="p-2 border-b border-default flex justify-between">
                        <button
                          onClick={selectAllSeverities}
                          className="text-xs text-primary hover:underline"
                        >
                          Select All
                        </button>
                        <button
                          onClick={clearAllSeverities}
                          className="text-xs text-muted hover:underline"
                        >
                          Clear
                        </button>
                      </div>
                      <div className="p-3 space-y-2">
                        <div className="text-xs text-muted mb-2">All</div>
                        {["critical", "high", "medium", "low"].map((severity) => {
                          const Icon = getSeverityIcon(severity);
                          const colorToken = getSeverityColorToken(severity);
                          const count = latestScan?.scan_results?.scans_findings ? Object.values(latestScan.scan_results.scans_findings)
                            .flat()
                            .filter(f => f.severity?.toLowerCase() === severity)
                            .length : 0;

                          return (
                            <label
                              key={severity}
                              className="flex items-center gap-3 p-2.5 rounded-full border-2 hover:shadow-sm cursor-pointer transition-all"
                              style={{
                                backgroundColor: selectedSeverities.includes(severity)
                                  ? `color-mix(in srgb, ${colorToken} 25%, var(--surface))`
                                  : 'transparent',
                                borderColor: selectedSeverities.includes(severity)
                                  ? `color-mix(in srgb, ${colorToken} 70%, var(--border))`
                                  : `color-mix(in srgb, var(--border) 80%, transparent)`,
                              }}
                            >
                              <input
                                type="checkbox"
                                checked={selectedSeverities.includes(severity)}
                                onChange={() => toggleSeverity(severity)}
                                className="w-4 h-4 rounded flex-shrink-0 accent-current cursor-pointer"
                                style={{ accentColor: colorToken }}
                              />
                              <span
                                className="text-sm font-semibold capitalize flex-1"
                                style={{ color: colorToken }}
                              >
                                {severity}
                              </span>
                              <span
                                className="text-xs font-bold"
                                style={{ color: colorToken }}
                              >
                                ({count})
                              </span>
                            </label>
                          );
                        })}
                      </div>
                    </motion.div>
                  )}
                </AnimatePresence>
              </div>

              {/* Type Filter Dropdown */}
              <div className="relative type-dropdown">
                <button
                  onClick={() => {
                    setTypeDropdownOpen(!typeDropdownOpen);
                    setSeverityDropdownOpen(false);
                  }}
                  className={`px-3 py-2 radius text-sm weight-medium transition-fast flex items-center gap-2 border ${selectedTypes.length > 0 && selectedTypes.length < 5
                    ? "bg-primary/10 border-primary/30 text-primary"
                    : selectedTypes.length === 5
                      ? "bg-elevated border-default text-muted"
                      : "bg-elevated border-default text-muted"
                    }`}
                >
                  <Filter className="w-4 h-4" />
                  <span>
                    Type {selectedTypes.length > 0 && selectedTypes.length < 5
                      ? `(${selectedTypes.length})`
                      : selectedTypes.length === 5
                        ? "(All)"
                        : "(0)"}
                  </span>
                  <ChevronDown className={`w-4 h-4 transition-transform ${typeDropdownOpen ? 'rotate-180' : ''}`} />
                </button>

                <AnimatePresence>
                  {typeDropdownOpen && (
                    <motion.div
                      initial={{ opacity: 0, y: -10 }}
                      animate={{ opacity: 1, y: 0 }}
                      exit={{ opacity: 0, y: -10 }}
                      transition={{ duration: 0.2 }}
                      className="absolute right-0 mt-2 w-48 bg-surface border border-default rounded-lg shadow-3 z-50 overflow-hidden"
                    >
                      <div className="p-2 border-b border-default flex justify-between">
                        <button
                          onClick={selectAllTypes}
                          className="text-xs text-primary hover:underline"
                        >
                          Select All
                        </button>
                        <button
                          onClick={clearAllTypes}
                          className="text-xs text-muted hover:underline"
                        >
                          Clear
                        </button>
                      </div>
                      {[
                        { id: "docker", label: "Docker", icon: Box },
                        { id: "kubernetes", label: "Kubernetes", icon: Layers },
                        { id: "terraform", label: "Terraform", icon: Cloud },
                        { id: "bicep", label: "Bicep", icon: FileCode },
                        { id: "arm", label: "ARM Template", icon: FileText },
                      ].map((type) => (
                        <label
                          key={type.id}
                          className="flex items-center gap-2 px-3 py-2 hover:bg-elevated cursor-pointer transition-fast"
                        >
                          <input
                            type="checkbox"
                            checked={selectedTypes.includes(type.id)}
                            onChange={() => toggleType(type.id)}
                            className="w-4 h-4 rounded border-default text-primary focus:ring-primary/30"
                          />
                          <span className={`text-sm capitalize flex items-center gap-1 ${getTypeTextColor(type.id)}`}>
                            <type.icon className="w-3 h-3" />
                            {type.label}
                          </span>
                        </label>
                      ))}
                    </motion.div>
                  )}
                </AnimatePresence>
              </div>

              {/* Active filters display */}
              {(selectedSeverities.length < 4 || selectedTypes.length < 5) && (
                <div className="flex items-center gap-2 text-xs">
                  <span className="text-muted">Active filters:</span>
                  {selectedSeverities.length < 4 && selectedSeverities.length > 0 && (
                    <span className="px-2 py-1 bg-elevated rounded-md text-muted">
                      {selectedSeverities.length} severity
                    </span>
                  )}
                  {selectedTypes.length < 5 && selectedTypes.length > 0 && (
                    <span className="px-2 py-1 bg-elevated radius text-muted">
                      {selectedTypes.length} type
                    </span>
                  )}
                </div>
              )}
            </div>
          </div>

          {/* TABLE VIEW */}
          <div className="overflow-x-auto rounded-lg border border-default bg-surface shadow-sm overflow-hidden" ref={tableRef}>
            <table className="w-full min-w-[900px]">
              <thead className="bg-[var(--table-head-bg)] figma-table-head border-b border-default">
                <tr>
                  <th className="px-6 py-3.5 text-center text-xs font-semibold text-text">Violation ID</th>
                  <th className="px-4 py-3.5 text-center text-xs font-semibold text-text">Severity</th>
                  <th className="px-4 py-3.5 text-center text-xs font-semibold text-text">Type</th>
                  <th className="px-4 py-3.5 text-center text-xs font-semibold text-text">Provider</th>
                  <th className="px-4 py-3.5 text-center text-xs font-semibold text-text">Title</th>
                  <th className="px-4 py-3.5 text-center text-xs font-semibold text-text">File</th>
                  <th className="px-6 py-3.5 text-center text-xs font-semibold text-text">Line</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-default">
                {filteredFindings.length > 0 ? (
                  filteredFindings.map((finding, index) => (
                    <tr key={index} className="group transition-colors hover:bg-elevated/40 border-b border-default">
                      <td className="px-6 py-3.5 align-middle text-xs font-mono font-medium text-text text-left">
                        <div className="flex justify-start">
                          <SmartTruncate text={finding.policyCode} maxLength={15} />
                        </div>
                      </td>
                      <td className="px-4 py-3.5 align-middle text-left">
                        <TableSeverityBadge severity={finding.severity} />
                      </td>
                      <td className="px-4 py-3.5 align-middle text-left">
                        <div className="flex justify-start">
                          <span className={`px-2 py-1 rounded-full text-xs font-medium capitalize flex items-center gap-1 w-fit ${getTypeBadgeStyle(finding.type)}`}>
                            {finding.type === "docker" && <Box className="w-3 h-3" />}
                            {finding.type === "kubernetes" && <Layers className="w-3 h-3" />}
                            {finding.type === "terraform" && <Cloud className="w-3 h-3" />}
                            {finding.type === "bicep" && <FileCode className="w-3 h-3" />}
                            {finding.type === "arm" && <FileText className="w-3 h-3" />}
                            {finding.type}
                          </span>
                        </div>
                      </td>
                      <td className="px-4 py-3.5 align-middle text-left">
                        {finding.provider && finding.provider !== finding.type ? (
                          <div className="flex justify-start">
                            <span className={`px-2 py-1 rounded-full text-xs font-medium capitalize ${getProviderBadgeStyle(finding.provider)}`}>
                              {finding.provider}
                            </span>
                          </div>
                        ) : null}
                      </td>
                      <td className="px-4 py-3.5 align-middle text-xs text-text max-w-md text-left">
                        <SmartTruncate text={finding.title} maxLength={60} />
                      </td>
                      <td className="px-4 py-3.5 align-middle text-xs text-muted text-left">
                        <SmartTruncate text={finding.file} maxLength={25} />
                      </td>
                      <td className="px-6 py-3.5 align-middle text-xs text-muted font-mono text-left">
                        {finding.lineNo !== "0" ? finding.lineNo : "-"}
                      </td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan="7" className="px-4 py-8 text-center text-muted">
                      No findings match your filter criteria
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>

          {/* Footer with count */}
          <div className="mt-4 pt-4 border-t border-default flex flex-wrap justify-between items-center gap-2">
            <p className="text-sm text-muted">
              Showing {filteredFindings.length} of {processedData.iacFindings.length} findings
            </p>
            <div className="flex flex-wrap gap-2 text-xs">
              <span className="px-2 py-1 bg-elevated rounded-md text-muted">
                Docker: {processedData.dockerFindings.length}
              </span>
              <span className="px-2 py-1 bg-elevated rounded-md text-muted">
                K8s: {processedData.kubernetesFindings.length}
              </span>
              <span className="px-2 py-1 bg-elevated rounded-md text-muted">
                Terraform: {processedData.terraformFindings.length}
              </span>
              <span className="px-2 py-1 bg-elevated radius text-muted">
                Bicep: {processedData.bicepFindings.length}
              </span>
            </div>
          </div>

          {/* Terraform Provider Breakdown in Footer */}
          {processedData.terraformFindings.length > 0 && (
            <div className="mt-2 flex justify-end gap-2 text-xs">
              <span className="text-muted">Terraform breakdown:</span>
              <span className="text-warning">AWS: {processedData.terraformAwsFindings.length}</span>
              <span className="text-info">Azure: {processedData.terraformAzureFindings.length}</span>
              <span className="text-success">GCP: {processedData.terraformGcpFindings.length}</span>
            </div>
          )}
        </div>
      </div>
      </main>
    </div>
  );
};

// ==================================================================
// SUPPORT COMPONENTS
// ==================================================================

const StatusCard = ({ label, status, filesScanned, findings }) => {
  const getStatusColor = (status) => {
    return status === "completed" ? "text-success" : "text-warning";
  };

  return (
    <div className="bg-surface rounded-lg shadow-2 p-4 border border-default">
      <div className="flex items-center justify-between mb-2">
        <span className="text-sm font-medium text">{label}</span>
        <span className={`text-xs ${getStatusColor(status)}`}>
          {status || "pending"}
        </span>
      </div>
      <div className="flex justify-between text-xs text-muted">
        <span>Files: {filesScanned || 0}</span>
        <span>Issues: {findings}</span>
      </div>
    </div>
  );
};

const ProviderCard = ({ provider, count, color }) => (
  <div className="bg-elevated rounded-lg p-3 border border-default">
    <div className="flex items-center justify-between">
      <span className="text-sm font-medium">{provider}</span>
      <span className="text-lg font-bold" style={{ color }}>{count}</span>
    </div>
  </div>
);

const LoadingState = () => (
  <div className="flex h-full min-h-[350px] items-center justify-center p-8">
    <div className="text-center p-6 max-w-md flex flex-col items-center gap-3">
      <div className="spinner w-10 h-10 mx-auto mb-2"></div>
      <p className="text-sm font-medium text-[var(--muted)]">Loading IaC scan data...</p>
    </div>
  </div>
);

const ErrorState = ({ error }) => (
  <div className="flex h-full min-h-[350px] items-center justify-center p-8">
    <div className="text-center p-6 max-w-md flex flex-col items-center gap-2">
      <AlertCircle className="w-10 h-10 text-danger mx-auto mb-2" />
      <h2 className="text-lg font-semibold text-[var(--text)] mb-1">Error Loading Data</h2>
      <p className="text-sm text-[var(--muted)]">{error}</p>
    </div>
  </div>
);

const EmptyState = ({ message = "No infrastructure as code security issues detected in this scan." }) => (
  <div className="flex h-full min-h-[350px] items-center justify-center p-8">
    <div className="text-center p-6 max-w-md flex flex-col items-center gap-2">
      <CheckCircle2 className="w-12 h-12 text-warning mx-auto mb-2" />
      <h2 className="text-lg font-semibold text-[var(--text)] mb-1">No IaC Issues Found</h2>
      <p className="text-sm text-[var(--muted)]">{message}</p>
    </div>
  </div>
);

const SummaryCard = ({ label, value, icon: Icon, color }) => (
  <div
    className="bg-surface rounded-md shadow-2 p-5 border border-default hover-lift transition-fast relative overflow-hidden group"
    style={{
      borderLeft: `4px solid ${color}`,
    }}
  >
    <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white to-transparent opacity-0 group-hover:opacity-5 transition-opacity"></div>
    <div className="flex items-center justify-between relative z-10">
      <div>
        <p className="text-sm text-muted mb-1">{label}</p>
        <p className="text-3xl font-bold text">{value}</p>
      </div>
      <div
        className="p-3 rounded-md transition-fast"
        style={{
          backgroundColor: `${color}20`,
          boxShadow: `0 0 12px ${color}30`,
        }}
      >
        <Icon className="w-6 h-6" style={{ color }} />
      </div>
    </div>
  </div>
);

// ==================================================================
// UTILITIES
// ==================================================================

const getSeverityBadgeStyle = (severity) => {
  return getFigmaSeverityBadgeStyle(severity);
};

const getTypeBadgeStyle = (type) => {
  const styles = {
    docker: "badge-cyan text-primary",
    kubernetes: "badge-blue text-low",
    terraform: "badge-purple text-secondary",
    bicep: "bg-sky-500/15 text-sky-400",
    arm: "bg-orange-500/15 text-orange-400",
  };
  return styles[type] || "bg-elevated text-muted";
};

const getProviderBadgeStyle = (provider) => {
  const styles = {
    aws: "badge-orange text-warning",
    azure: "badge-blue text-info",
    gcp: "badge-green text-success",
  };
  return styles[provider] || "bg-elevated text-muted";
};

const getSeverityTextColor = (severity) => {
  const styles = {
    critical: "text-critical",
    high: "text-high",
    medium: "text-medium",
    low: "text-low",
  };
  return styles[severity] || "text-muted";
};

const getTypeTextColor = (type) => {
  const styles = {
    docker: "text-primary",
    kubernetes: "text-low",
    terraform: "text-secondary",
    bicep: "text-sky-400",
    arm: "text-orange-400",
  };
  return styles[type] || "text-muted";
};

export default IaCDashboard;