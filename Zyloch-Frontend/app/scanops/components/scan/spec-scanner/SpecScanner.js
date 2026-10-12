"use client";

import React, { useEffect, useMemo, useRef, useState } from "react";
import dynamic from "next/dynamic";
import { useScanStore } from "@/store/useScanStore";
import { useNavbar } from "@/hooks/useNavbar";
import {
  AlertCircle,
  AlertTriangle,
  Calendar,
  Check,
  ChevronDown,
  ChevronLeft,
  ChevronRight,
  Eye,
  FileText,
  GitBranch,
  GitCommitHorizontal,
  Link2,
  Loader2,
  Play,
  Search,
  ShieldCheck,
  User,
  X,
  Filter,
} from "lucide-react";
import { formatApiText } from "../shared/textUtils";
import {
  formatSeverityLabel,
  getSeverityBadgeStyle as getSharedSeverityBadgeStyle,
  getSeverityIcon,
  getSeverityColorToken,
  SEVERITY_FIGMA_COLORS,
  getFigmaSeverityBadgeStyle,
  normalizeSeverity,
  TableSeverityBadge,
} from "../shared/severityVisuals";
import styles from "../workflow/Workflow.module.css";
import TechStackIcon from "@/components/common/TechStackIcon";
import PolicyDetailsSidebar from "../iac/PolicyDetailsSidebar";
import { useInteractiveTable } from "../shared/useInteractiveTable";
import IssuesBySeverityCard from "../shared/IssuesBySeverityCard";
import SecurityScoreCard from "../shared/SecurityScoreCard";
import ScanMetadataOverview from "../shared/ScanMetadataOverview";

const BarChartUI = dynamic(() => import("@/components/charts/BarChartUI"), {
  ssr: false,
  loading: () => <div className={styles.chartLoading}>Loading Chart...</div>,
});

const PieChartUI = dynamic(() => import("@/components/charts/PieChartUI"), {
  ssr: false,
  loading: () => <div className={styles.chartLoading}>Loading Chart...</div>,
});

const SEVERITY_ORDER = ["critical", "high", "medium", "low"];
const PAGE_SIZE_OPTIONS = [10, 25, 50, 100];
const FORCE_DUMMY_DATA_ONLY = false;

const DUMMY_DATA = {
  score: 62,
  severityCounts: { critical: 3, high: 7, medium: 12, low: 5 },
  totalViolations: 27,
  totalApis: 14,
  vulnerableApis: 6,
  checksFailed: 5,
  scanMetadata: {
    organization: "acme-corp",
    repository: "api-gateway",
    commit_author: "jane.doe",
    branch: "main",
    scan_timestamp: new Date().toISOString(),
  },
  checks: [
    { id: "OWASP-API1", name: "Broken Object Level Authorization", description: "API endpoints should validate object-level permissions before returning data.", status: "failed", severity: "critical" },
    { id: "OWASP-API2", name: "Broken Authentication", description: "Authentication mechanisms must be correctly implemented across all endpoints.", status: "failed", severity: "high" },
    { id: "OWASP-API3", name: "Broken Object Property Level Authorization", description: "Validate that users can only access object properties they are authorized for.", status: "passed", severity: "medium" },
    { id: "OWASP-API4", name: "Unrestricted Resource Consumption", description: "Rate limiting and resource quotas should be enforced.", status: "failed", severity: "high" },
    { id: "OWASP-API5", name: "Broken Function Level Authorization", description: "Administrative endpoints must be protected from unauthorized access.", status: "passed", severity: "high" },
    { id: "OWASP-API6", name: "Unrestricted Access to Sensitive Business Flows", description: "Sensitive business logic flows should be protected against automated abuse.", status: "failed", severity: "medium" },
    { id: "OWASP-API7", name: "Server Side Request Forgery", description: "Validate and sanitize user-supplied URLs to prevent SSRF attacks.", status: "passed", severity: "high" },
    { id: "OWASP-API8", name: "Security Misconfiguration", description: "Ensure TLS, CORS, and security headers are configured correctly.", status: "failed", severity: "medium" },
    { id: "OWASP-API9", name: "Improper Inventory Management", description: "Keep an accurate inventory of API versions and deprecate old ones.", status: "passed", severity: "low" },
    { id: "OWASP-API10", name: "Unsafe Consumption of APIs", description: "Validate and sanitize data received from third-party APIs.", status: "passed", severity: "medium" },
  ],
  apis: [
    { method: "GET", path: "/api/v1/users/{id}", secure: false, description: "Retrieve a user by ID", file: "openapi.yaml", line: 42 },
    { method: "POST", path: "/api/v1/users", secure: true, description: "Create a new user", file: "openapi.yaml", line: 60 },
    { method: "DELETE", path: "/api/v1/users/{id}", secure: false, description: "Delete a user by ID", file: "openapi.yaml", line: 78 },
    { method: "GET", path: "/api/v1/orders", secure: true, description: "List all orders for current user", file: "openapi.yaml", line: 95 },
    { method: "POST", path: "/api/v1/orders", secure: true, description: "Place a new order", file: "openapi.yaml", line: 113 },
    { method: "GET", path: "/api/v1/orders/{id}", secure: false, description: "Retrieve order by ID", file: "openapi.yaml", line: 130 },
    { method: "PUT", path: "/api/v1/orders/{id}", secure: false, description: "Update an order", file: "openapi.yaml", line: 148 },
    { method: "GET", path: "/api/v1/products", secure: true, description: "List all products", file: "openapi.yaml", line: 165 },
    { method: "POST", path: "/api/v1/payments", secure: false, description: "Initiate a payment", file: "openapi.yaml", line: 182 },
    { method: "GET", path: "/api/v1/payments/{id}", secure: false, description: "Retrieve payment details", file: "openapi.yaml", line: 199 },
    { method: "GET", path: "/api/v1/admin/users", secure: true, description: "Admin: list all users", file: "openapi.yaml", line: 216 },
    { method: "POST", path: "/api/v1/upload", secure: false, description: "Upload a file", file: "openapi.yaml", line: 233 },
    { method: "GET", path: "/api/v1/health", secure: true, description: "Health check endpoint", file: "openapi.yaml", line: 250 },
    { method: "GET", path: "/api/v1/config", secure: false, description: "Retrieve service configuration", file: "openapi.yaml", line: 267 },
  ],
  findingsRows: [
    { id: "d-1", type: "OWASP", rule: "OWASP-API1", severity: "critical", method: "GET", endpoint: "/api/v1/users/{id}", category: "BOLA", message: "No object-level authorization check found on user retrieval endpoint.", location: "openapi.yaml:42" },
    { id: "d-2", type: "OWASP", rule: "OWASP-API1", severity: "critical", method: "DELETE", endpoint: "/api/v1/users/{id}", category: "BOLA", message: "Endpoint allows deletion without validating ownership of the resource.", location: "openapi.yaml:78" },
    { id: "d-3", type: "OWASP", rule: "OWASP-API2", severity: "critical", method: "POST", endpoint: "/api/v1/payments", category: "Authentication", message: "Payment initiation endpoint has no authentication scheme defined.", location: "openapi.yaml:182" },
    { id: "d-4", type: "OWASP", rule: "OWASP-API2", severity: "high", method: "GET", endpoint: "/api/v1/orders/{id}", category: "Authentication", message: "Order retrieval endpoint is missing bearer token authentication.", location: "openapi.yaml:130" },
    { id: "d-5", type: "OWASP", rule: "OWASP-API4", severity: "high", method: "POST", endpoint: "/api/v1/upload", category: "Rate Limiting", message: "No rate limit or file size restriction defined on upload endpoint.", location: "openapi.yaml:233" },
    { id: "d-6", type: "OWASP", rule: "OWASP-API4", severity: "high", method: "GET", endpoint: "/api/v1/products", category: "Rate Limiting", message: "Pagination is not enforced; endpoint could return unbounded data sets.", location: "openapi.yaml:165" },
    { id: "d-7", type: "OWASP", rule: "OWASP-API6", severity: "high", method: "POST", endpoint: "/api/v1/orders", category: "Business Flows", message: "Order placement flow lacks automated-abuse protection.", location: "openapi.yaml:113" },
    { id: "d-8", type: "OWASP", rule: "OWASP-API8", severity: "high", method: "GET", endpoint: "/api/v1/config", category: "Misconfiguration", message: "Configuration endpoint exposed without proper security headers.", location: "openapi.yaml:267" },
    { id: "d-9", type: "PAYLOAD", rule: "SCHEMA-001", severity: "medium", method: "POST", endpoint: "/api/v1/users", category: "Schema Validation", message: "Request body is missing strict type validation for the 'email' field.", location: "openapi.yaml:60" },
    { id: "d-10", type: "PAYLOAD", rule: "SCHEMA-002", severity: "medium", method: "PUT", endpoint: "/api/v1/orders/{id}", category: "Response Schema", message: "Response schema for 4xx error codes is not defined.", location: "openapi.yaml:148" },
    { id: "d-11", type: "PAYLOAD", rule: "SCHEMA-003", severity: "medium", method: "POST", endpoint: "/api/v1/payments", category: "Input Validation", message: "Amount field allows negative values; no minimum constraint is set.", location: "openapi.yaml:182" },
    { id: "d-12", type: "PAYLOAD", rule: "SCHEMA-001", severity: "medium", method: "GET", endpoint: "/api/v1/admin/users", category: "Schema Validation", message: "Response body leaks internal user IDs and hashed passwords.", location: "openapi.yaml:216" },
    { id: "d-13", type: "OWASP", rule: "OWASP-API8", severity: "medium", method: "GET", endpoint: "/api/v1/health", category: "Misconfiguration", message: "Health check returns verbose stack trace on failure.", location: "openapi.yaml:250" },
    { id: "d-14", type: "PAYLOAD", rule: "SCHEMA-004", severity: "medium", method: "POST", endpoint: "/api/v1/upload", category: "Content Type", message: "MIME type validation is absent; any content-type is accepted.", location: "openapi.yaml:233" },
    { id: "d-15", type: "OWASP", rule: "OWASP-API8", severity: "medium", method: "GET", endpoint: "/api/v1/config", category: "Misconfiguration", message: "CORS policy is set to wildcard (*) allowing any origin.", location: "openapi.yaml:267" },
    { id: "d-16", type: "PAYLOAD", rule: "SCHEMA-002", severity: "low", method: "GET", endpoint: "/api/v1/users/{id}", category: "Response Schema", message: "Missing 404 response schema for non-existent user IDs.", location: "openapi.yaml:42" },
    { id: "d-17", type: "PAYLOAD", rule: "SCHEMA-003", severity: "low", method: "GET", endpoint: "/api/v1/orders", category: "Input Validation", message: "Cursor-based pagination parameters are undocumented.", location: "openapi.yaml:95" },
    { id: "d-18", type: "OWASP", rule: "OWASP-API9", severity: "low", method: "GET", endpoint: "/api/v1/products", category: "Inventory", message: "API version is not included in the path; old versions may still be active.", location: "openapi.yaml:165" },
    { id: "d-19", type: "PAYLOAD", rule: "SCHEMA-004", severity: "low", method: "POST", endpoint: "/api/v1/orders", category: "Content Type", message: "Enum values for order status are not validated in the request schema.", location: "openapi.yaml:113" },
    { id: "d-20", type: "PAYLOAD", rule: "SCHEMA-001", severity: "low", method: "DELETE", endpoint: "/api/v1/users/{id}", category: "Schema Validation", message: "No 204 No-Content response schema documented for successful deletion.", location: "openapi.yaml:78" },
  ],
  insights: {
    cucumberSummary: {
      totalScenarios: 58,
      passed: 46,
      failed: 9,
      skipped: 3,
      passRate: "79.31%",
      executionTimeSeconds: 412,
    },
    cucumberReport: [
      {
        feature: "Authentication and Session Management",
        scenarios: 14,
        passed: 11,
        failed: 3,
        tags: ["auth", "critical"],
      },
      {
        feature: "Payment Flow Integrity",
        scenarios: 18,
        passed: 15,
        failed: 2,
        skipped: 1,
        tags: ["payment", "high"],
      },
      {
        feature: "Order and Inventory APIs",
        scenarios: 26,
        passed: 20,
        failed: 4,
        skipped: 2,
        tags: ["orders", "medium"],
      },
    ],
    relationsBetweenApi: {
      apiLinks: [
        { from: "POST /api/v1/orders", to: "POST /api/v1/payments", type: "depends-on", via: "routes/order.route.js" },
        { from: "GET /api/v1/orders/{id}", to: "GET /api/v1/users/{id}", type: "uses-identity", via: "routes/order.route.js" },
        { from: "POST /api/v1/upload", to: "GET /api/v1/config", type: "policy-lookup", via: "routes/upload.route.js" },
        { from: "DELETE /api/v1/users/{id}", to: "GET /api/v1/users/{id}", type: "shares-file", via: "routes/user.route.js" },
      ],
      nodes: [
        { id: "GET /api/v1/users/{id}", method: "GET", path: "/api/v1/users/{id}", protocol: "REST", file: "routes/user.route.js", line: 42 },
        { id: "POST /api/v1/orders", method: "POST", path: "/api/v1/orders", protocol: "REST", file: "routes/order.route.js", line: 113 },
        { id: "GET /api/v1/orders/{id}", method: "GET", path: "/api/v1/orders/{id}", protocol: "REST", file: "routes/order.route.js", line: 130 },
        { id: "POST /api/v1/payments", method: "POST", path: "/api/v1/payments", protocol: "REST", file: "routes/payment.route.js", line: 182 },
        { id: "POST /api/v1/upload", method: "POST", path: "/api/v1/upload", protocol: "REST", file: "routes/upload.route.js", line: 233 },
      ],
      edges: [
        { from: "POST /api/v1/orders", to: "POST /api/v1/payments", type: "depends-on", via: "routes/order.route.js" },
        { from: "GET /api/v1/orders/{id}", to: "GET /api/v1/users/{id}", type: "uses-identity", via: "routes/order.route.js" },
        { from: "POST /api/v1/upload", to: "GET /api/v1/config", type: "policy-lookup", via: "routes/upload.route.js" },
        { from: "DELETE /api/v1/users/{id}", to: "GET /api/v1/users/{id}", type: "shares-file", via: "routes/user.route.js" },
      ],
      summary: {
        nodes: 5,
        edges: 4,
        protocols: { REST: 5 },
        edgeTypes: { "depends-on": 1, "uses-identity": 1, "policy-lookup": 1, "shares-file": 1 },
      },
    },
    nativeSpecs: {
      graphql: { enabled: true, schemaFiles: ["schema.graphql"], operations: 24 },
      grpc: { enabled: false, protoFiles: [] },
      soap: { enabled: false, wsdlFiles: [] },
    },
    previous: {
      runId: "spec-scanner-2026-05-05T11:10:00Z",
      failedScenarios: 12,
      vulnerableApis: 8,
      totalViolations: 33,
    },
    current: {
      runId: "spec-scanner-2026-05-06T11:10:00Z",
      failedScenarios: 9,
      vulnerableApis: 6,
      totalViolations: 27,
    },
    difference: {
      previous: { scanId: "spec-scanner-prev-2026-05-05" },
      current: { scanId: "spec-scanner-curr-2026-05-06", scanResultPath: "/app/output/history/acme-corp/api-gateway/result.json" },
      spec: {
        added: [], removed: [], modified: [], breakingChanges: [],
        summary: { added: 0, removed: 0, modified: 0, breaking: 0, firstScan: false },
      },
      cucumber: {
        fixed: ["OWASP-API2", "OWASP-API4"], regressed: ["SCHEMA-004"], unchanged: [], newIssues: [],
        summary: { fixed: 2, regressed: 1, unchanged: 24, newIssues: 0, firstScan: false },
      },
      issues: {
        fixed: [
          { type: "OWASP", scenarioId: "owasp-api2", scenarioName: "Validate authentication mechanisms", message: "Endpoint POST /api/v1/users now enforces authentication." },
          { type: "OWASP", scenarioId: "owasp-api4", scenarioName: "Unrestricted Resource Consumption", message: "Rate limiting applied on upload endpoint." },
        ],
        pending: [
          { type: "OWASP", scenarioId: "owasp-api1", scenarioName: "Validate authorization on object access", message: "Endpoint GET /api/v1/users/{id} does not enforce authentication." },
          { type: "OWASP", scenarioId: "owasp-api1", scenarioName: "Validate authorization on object access", message: "Endpoint DELETE /api/v1/users/{id} lacks ownership validation." },
          { type: "PAYLOAD", scenarioId: "schema-004", scenarioName: "Unsafe Consumption of APIs", message: "MIME type validation absent on POST /api/v1/upload." },
        ],
        difference: { new: [], resolved: ["owasp-api2", "owasp-api4"] },
        summary: { fixed: 2, pending: 25, new: 0, firstScan: false },
      },
    },
    specSummary: {
      openApiVersion: "3.0.3",
      totalPaths: 14,
      securedPaths: 8,
      unsecuredPaths: 6,
    },
    issuesMeta: {
      new: 4,
      fixed: 9,
      unchanged: 14,
      differenceScore: 18,
    },
    payloadViolationSummary: {
      schemaTypeMismatch: 5,
      missingRequiredField: 3,
      weakValidation: 6,
    },
  },
};

const getPaginationPages = (current, total) => {
  if (total <= 7) return Array.from({ length: total }, (_, i) => i + 1);
  if (current <= 4) return [1, 2, 3, 4, 5, "...", total];
  if (current >= total - 3) return [1, "...", total - 4, total - 3, total - 2, total - 1, total];
  return [1, "...", current - 1, current, current + 1, "...", total];
};

const SpecScanner = () => {
  const { latestScan, loading, error } = useScanStore();
  const { selectedInstallation } = useNavbar();
  const [query, setQuery] = useState("");
  // ── Direct spec-scanner state ───────────────────────────────────────────
  const [directScanPath, setDirectScanPath] = useState("");
  const [directScanRunning, setDirectScanRunning] = useState(false);
  const [directScanError, setDirectScanError] = useState(null);
  const [directScanResult, setDirectScanResult] = useState(null); // raw API response

  const runDirectScan = async () => {
    if (!directScanPath.trim()) return;
    setDirectScanRunning(true);
    setDirectScanError(null);
    setDirectScanResult(null);

    const meta = latestScan?.scan_metadata || {};
    try {
      const res = await fetch("/api/spec-scanner/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          path: directScanPath.trim(),
          scan_metadata: {
            organization: meta.organization || "unknown",
            repository: meta.repository || "unknown",
            branch: meta.branch || "main",
            commit_hash: meta.commit_hash || "HEAD",
            commit_author: meta.commit_author || null,
            scan_type: "spec-scanner",
          },
        }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        setDirectScanError(data?.error || `Request failed (${res.status})`);
      } else {
        setDirectScanResult(data);
      }
    } catch (err) {
      setDirectScanError(err instanceof Error ? err.message : "Network error");
    } finally {
      setDirectScanRunning(false);
    }
  };

  const [selectedSeverities, setSelectedSeverities] = useState(SEVERITY_ORDER);
  const [selectedRules, setSelectedRules] = useState(null); // null = all
  const [severityDropdownOpen, setSeverityDropdownOpen] = useState(false);
  const [ruleDropdownOpen, setRuleDropdownOpen] = useState(false);
  const [pageSizeDropdownOpen, setPageSizeDropdownOpen] = useState(false);
  const [currentPage, setCurrentPage] = useState(1);
  const [pageSize, setPageSize] = useState(25);
  const [selectedFinding, setSelectedFinding] = useState(null);
  const [isSidebarOpen, setIsSidebarOpen] = useState(false);
  const [reportView, setReportView] = useState("spec-findings");
  const tableRef = useRef(null);

  useEffect(() => {
    const handleClickOutside = (e) => {
      if (!e.target.closest(".spec-severity-dropdown")) {
        setSeverityDropdownOpen(false);
      }
      if (!e.target.closest(".spec-rule-dropdown")) {
        setRuleDropdownOpen(false);
      }
      if (!e.target.closest(".spec-pagesize-dropdown")) {
        setPageSizeDropdownOpen(false);
      }
    };
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);

  const hasScanError = Boolean(error);

  const latestCreatedAt = latestScan?.created_at;
  const root = hasScanError ? {} : (latestScan || {});
  const rootScanResults = root?.scan_results || {};
  const nestedScanResults = rootScanResults?.scan_results || rootScanResults;
  const summary = nestedScanResults?.summary || rootScanResults?.summary || root?.summary || {};
  const scannerResults =
    nestedScanResults?.scanner_results ||
    rootScanResults?.scanner_results ||
    root?.scanner_results ||
    {};
  const scannerNode = scannerResults?.["spec-scanner"] || {};
  const scoreBySubscan = summary?.score_summary?.score_by_subscan || {};
  const issueCountsBySubscan = summary?.issues_summary?.issue_counts_by_subscan_and_severity || {};
  const specSummarySeverity = issueCountsBySubscan?.["spec-scanner"] || {};
  // generator_validator is set by the backend when spec-scanner runs as part of a full scan
  const generatorValidator =
    nestedScanResults?.generator_validator ||
    rootScanResults?.generator_validator ||
    root?.generator_validator ||
    scannerNode?.metadata?.spec_scan_response ||
    {};
  // When a direct scan was triggered from the UI, it takes priority over stored scan data.
  // The spec generator returns { scan: {...} } which matches the generatorValidator shape.
  const effectiveGeneratorValidator = directScanResult ?? generatorValidator;

  const specScan = effectiveGeneratorValidator?.scan || scannerNode?.metadata?.spec_scan_response?.scan || {};
  const specMeta = specScan?.meta || {};
  const checks = Array.isArray(specScan?.checks) ? specScan.checks : [];
  const apis = Array.isArray(specScan?.apis) ? specScan.apis : [];
  const apiViolations = Array.isArray(specScan?.apiViolations) ? specScan.apiViolations : [];
  const payloadViolations = Array.isArray(specScan?.payloadViolations)
    ? specScan.payloadViolations
    : [];

  const scanFindings =
    nestedScanResults?.scans_findings ||
    rootScanResults?.scans_findings ||
    root?.scans_findings ||
    {};
  const fallbackFindings = Array.isArray(scanFindings?.["Spec-Scanner-findings"])
    ? scanFindings["Spec-Scanner-findings"]
    : Array.isArray(scanFindings?.["spec-scanner-findings"])
      ? scanFindings["spec-scanner-findings"]
      : [];

  const findingsRows = useMemo(() => {
    // Group the spec-generator's payloadViolations by endpoint (METHOD PATH) so
    // each endpoint finding can carry its related request/response payload
    // issues. These are surfaced in the details sidebar (not as a table column).
    const payloadByEndpoint = {};
    payloadViolations.forEach((violation) => {
      if (!violation?.path) return;
      const key = `${String(violation.method || "").toUpperCase()} ${violation.path}`;
      (payloadByEndpoint[key] = payloadByEndpoint[key] || []).push(violation);
    });
    const lookupPayload = (method, path) =>
      path ? payloadByEndpoint[`${String(method || "").toUpperCase()} ${path}`] || [] : [];

    const formatSourceLocation = (file, line) => {
      if (!file) return null;
      if (line !== null && line !== undefined && line !== "" && line !== "-") {
        return `${file}:${line}`;
      }
      return String(file);
    };

    const fromApiViolations = apiViolations.map((violation, idx) => {
      const file = violation.file || null;
      const line = violation.line ?? null;
      return {
        id: `api-${idx}-${violation.violationId || "rule"}`,
        type: "spec-scanner",
        rule: violation.violationId || "N/A",
        severity: String(violation.severity || "medium").toLowerCase(),
        method: violation.method ? String(violation.method).toUpperCase() : "N/A",
        // Endpoint column shows path only; Method has its own column.
        endpoint: formatPath(violation.path),
        file,
        line,
        message: violation.message || "N/A",
        location: formatSourceLocation(file, line) || violation.path || "N/A",
        protocol: violation.protocol || "REST",
        category: violation.category || getCategoryFromRule(violation.violationId, violation.message),
        payload: violation.payload || null,
        payloadViolations: lookupPayload(violation.method, violation.path),
        codeBlock: violation.code_block || violation.codeBlock || null,
      };
    });

    const fromPayload = payloadViolations.map((violation, idx) => {
      const file = violation.file || null;
      const line = violation.line ?? null;
      return {
        id: `payload-${idx}-${violation.rule || "rule"}`,
        type: "spec-scanner",
        rule: violation.rule || "N/A",
        severity: String(violation.severity || "medium").toLowerCase(),
        method: violation.method ? String(violation.method).toUpperCase() : "N/A",
        endpoint: formatPath(violation.path),
        file,
        line,
        message: violation.message || "N/A",
        // Prefer source file:line; fall back to schema location (requestBody/response/…).
        location: formatSourceLocation(file, line) || violation.location || "N/A",
        protocol: violation.protocol || "REST",
        category: violation.category || getCategoryFromRule(violation.rule, violation.message),
        payload: null,
        payloadViolations: [violation],
        codeBlock: violation.code_block || violation.codeBlock || null,
      };
    });

    if (fromApiViolations.length || fromPayload.length) {
      return [...fromApiViolations, ...fromPayload];
    }

    if (fallbackFindings.length) {
      return fallbackFindings.flatMap((item, idx) => {
        // file_name is the endpoint ("POST /api/order"); `file` is the real source path.
        const endpointKey = item?.file_name || "N/A";
        const sourceFile = item?.file || null;
        const policies = Array.isArray(item?.violated_policies) ? item.violated_policies : [];
        return policies.map((policy, policyIdx) => {
          const line = policy.Line_No ?? policy.line_no ?? null;
          const methodMatch = String(endpointKey).match(
            /^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|TRACE)\s+(\S+)/i
          );
          return {
            id: `fallback-${idx}-${policyIdx}`,
            type: "spec-scanner",
            rule: policy.policy_name || policy.policy_code || "N/A",
            severity: String(policy.severity || "medium").toLowerCase(),
            method: methodMatch ? methodMatch[1].toUpperCase() : "N/A",
            endpoint: methodMatch ? formatPath(methodMatch[2]) : endpointKey,
            file: sourceFile,
            line,
            message: policy.description || policy.Matches || "N/A",
            location:
              formatSourceLocation(sourceFile, line) ||
              endpointKey,
            codeBlock: policy.code_block || policy.codeBlock || null,
          };
        });
      });
    }

    return [];
  }, [apiViolations, payloadViolations, fallbackFindings]);

  const useDummy = FORCE_DUMMY_DATA_ONLY;

  const activeChecks = useDummy ? DUMMY_DATA.checks : checks;
  const activeApis = useDummy ? DUMMY_DATA.apis : apis;
  const activeFindingsRows = useDummy ? DUMMY_DATA.findingsRows : findingsRows;

  const score = useDummy
    ? DUMMY_DATA.score
    : clamp(Number(scoreBySubscan?.["spec-scanner"] ?? 0), 0, 100);

  const ringRadius = 42;
  const ringCircumference = 2 * Math.PI * ringRadius;
  const ringOffset = ringCircumference * (1 - score / 100);

  const severityCounts = useDummy ? DUMMY_DATA.severityCounts : {
    critical:
      Number(specMeta?.severityCounts?.critical) ||
      Number(specSummarySeverity?.critical) ||
      0,
    high:
      Number(specMeta?.severityCounts?.high) ||
      Number(specSummarySeverity?.high) ||
      0,
    medium:
      Number(specMeta?.severityCounts?.medium) ||
      Number(specSummarySeverity?.medium) ||
      0,
    low:
      Number(specMeta?.severityCounts?.low) ||
      Number(specSummarySeverity?.low) ||
      0,
  };

  const severityData = SEVERITY_ORDER.map((level) => ({
    name: formatApiText(level),
    value: severityCounts[level] || 0,
    color: getSeverityColor(level),
  })).filter((item) => item.value > 0);

  const checkStatusData = [
    {
      name: "Passed",
      value: Number(specMeta?.passed || activeChecks.filter((c) => normalizeStatus(c.status) === "passed").length || 0),
      color: "var(--success)",
    },
    {
      name: "Failed",
      value: Number(specMeta?.failed || activeChecks.filter((c) => normalizeStatus(c.status) === "failed").length || 0),
      color: "var(--danger)",
    },
  ].filter((item) => item.value > 0);

  const ruleOptions = useMemo(() => {
    const values = new Set();
    activeFindingsRows.forEach((row) => values.add(row.rule));
    return Array.from(values).sort((a, b) => a.localeCompare(b));
  }, [activeFindingsRows]);

  const specInsights = useMemo(() => {
    if (useDummy) {
      return {
        cucumberSummary: DUMMY_DATA.insights.cucumberSummary,
        cucumberReport: DUMMY_DATA.insights.cucumberReport,
        relationsBetweenApi: DUMMY_DATA.insights.relationsBetweenApi,
        nativeSpecs: DUMMY_DATA.insights.nativeSpecs,
        difference: DUMMY_DATA.insights.difference,
        previous: DUMMY_DATA.insights.previous,
        current: DUMMY_DATA.insights.current,
        specSummary: DUMMY_DATA.insights.specSummary,
        issuesMeta: DUMMY_DATA.insights.issuesMeta,
        payloadViolationSummary: DUMMY_DATA.insights.payloadViolationSummary,
        checksWithMeta: (activeChecks || []).map((check) => ({
          id: check.id,
          name: check.name,
          status: check.status,
          severity: check.severity,
          description: check.description,
          tags: check.tags,
        })),
        apisWithMeta: (activeApis || []).map((api) => ({
          method: api.method,
          path: api.path,
          description: api.description || api.summary,
          file: api.file,
          line: api.line,
          secure: api.secure,
        })),
        hasAny: true,
      };
    }

    const fullResponse = effectiveGeneratorValidator || scannerNode?.metadata?.spec_scan_response || {};
    const scan = fullResponse?.scan || fullResponse?.scan_data || {};
    const source = Object.keys(scan || {}).length ? scan : fullResponse;
    const cucumberBlock = source?.cucumber || source?.cucumber_report || {};

    const checksWithMeta = (activeChecks || []).map((check) => ({
      id: check.id,
      name: check.name,
      status: check.status,
      severity: check.severity,
      description: check.description,
      tags: check.tags,
    }));

    const apisWithMeta = (activeApis || []).map((api) => ({
      method: api.method,
      path: api.path,
      description: api.description || api.summary,
      file: api.file,
      line: api.line,
      secure: api.secure,
    }));

    const cucumberSummary =
      cucumberBlock?.summary ||
      cucumberBlock?.cucumber_summary ||
      source?.cucumberSummary ||
      source?.cucumber_summary ||
      null;

    const cucumberReport =
      source?.cucumberReport ||
      source?.cucumber_report ||
      cucumberBlock?.report ||
      cucumberBlock?.cucumber_report ||
      null;

    // relationsBetweenApi and difference are emitted as SIBLINGS of `scan`
    // (i.e. on fullResponse), not inside it — so fall back to fullResponse.
    const relationsBetweenApi =
      source?.relationsBetweenApi ||
      source?.relations_between_api ||
      source?.relationshipApi ||
      source?.relationship_api ||
      fullResponse?.relationsBetweenApi ||
      fullResponse?.relations_between_api ||
      null;

    const difference =
      source?.difference ||
      source?.scan_difference ||
      fullResponse?.difference ||
      fullResponse?.scan_difference ||
      null;

    return {
      cucumberSummary,
      cucumberReport,
      relationsBetweenApi,
      nativeSpecs: source?.nativeSpecs || source?.native_specs || null,
      difference,
      previous: source?.previous || source?.prev || null,
      current: source?.current || null,
      specSummary: source?.spec?.summary || source?.specSummary || source?.spec_summary || null,
      issuesMeta: source?.issues || source?.issues_meta || null,
      payloadViolationSummary: source?.payloadViolationSummary || source?.payload_violation_summary || null,
      checksWithMeta,
      apisWithMeta,
      hasAny:
        Boolean(cucumberSummary) ||
        Boolean(cucumberReport) ||
        Boolean(relationsBetweenApi) ||
        Boolean(source?.nativeSpecs || source?.native_specs) ||
        Boolean(difference) ||
        Boolean(source?.previous || source?.prev) ||
        Boolean(source?.current) ||
        Boolean(source?.spec?.summary || source?.specSummary || source?.spec_summary) ||
        Boolean(source?.issues || source?.issues_meta) ||
        Boolean(source?.payloadViolationSummary || source?.payload_violation_summary),
    };
  }, [effectiveGeneratorValidator, scannerNode, activeChecks, activeApis, useDummy, directScanResult]);

  const isFindingsView = reportView === "spec-findings";

  useEffect(() => {
    const handleClickOutside = (event) => {
      if (!(event.target instanceof Element)) return;

      if (
        !event.target.closest(".spec-severity-dropdown") &&
        !event.target.closest(".spec-rule-dropdown")
      ) {
        setSeverityDropdownOpen(false);
        setRuleDropdownOpen(false);
      }
    };

    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);

  const toggleSeverity = (sev) => {
    setSelectedSeverities((prev) =>
      prev.includes(sev) ? prev.filter((s) => s !== sev) : [...prev, sev]
    );
    setCurrentPage(1);
  };
  const selectAllSeverities = () => {
    setSelectedSeverities(SEVERITY_ORDER);
    setCurrentPage(1);
  };
  const clearAllSeverities = () => {
    setSelectedSeverities([]);
    setCurrentPage(1);
  };

  const toggleRule = (rule) => {
    const current = selectedRules ?? ruleOptions;
    const next = current.includes(rule) ? current.filter((r) => r !== rule) : [...current, rule];
    setSelectedRules(next.length === ruleOptions.length ? null : next);
    setCurrentPage(1);
  };
  const selectAllRules = () => {
    setSelectedRules(null);
    setCurrentPage(1);
  };
  const clearAllRules = () => {
    setSelectedRules([]);
    setCurrentPage(1);
  };

  const hasPartialSeverity = selectedSeverities.length > 0 && selectedSeverities.length < SEVERITY_ORDER.length;
  const hasAllSeverities = selectedSeverities.length === SEVERITY_ORDER.length;

  const hasAllRules = selectedRules === null || selectedRules.length === ruleOptions.length;
  const hasPartialRules = selectedRules !== null && selectedRules.length > 0 && selectedRules.length < ruleOptions.length;

  const filteredFindingsRows = useMemo(() => {
    const q = query.trim().toLowerCase();
    const activeRules = selectedRules ?? ruleOptions;

    return activeFindingsRows.filter((row) => {
      if (!hasAllSeverities && !selectedSeverities.includes(row.severity)) return false;
      if (!hasAllRules && !activeRules.includes(row.rule)) return false;
      if (!q) return true;

      const text = [row.type, row.rule, row.endpoint, row.message, row.location, row.file]
        .filter(Boolean)
        .join(" ")
        .toLowerCase();
      return text.includes(q);
    });
  }, [activeFindingsRows, query, selectedRules, hasAllRules, ruleOptions, selectedSeverities, hasAllSeverities]);

  const nonFindingsConfig = useMemo(() => {
    const q = query.trim().toLowerCase();

    if (reportView === "cucumber-report") {
      const raw = specInsights.cucumberReport;
      let reportItems = [];

      if (Array.isArray(raw)) {
        reportItems = raw;
      } else if (Array.isArray(raw?.features)) {
        reportItems = raw.features;
      } else if (Array.isArray(raw?.items)) {
        reportItems = raw.items;
      }

      const baseRowsFromReport = reportItems.map((item, idx) => ({
        id: `cucumber-${idx}`,
        feature: item.feature || item.name || item.scenarioName || "N/A",
        scenarios: Number(item.scenarios ?? item.totalScenarios ?? 0),
        passed: Number(item.passed ?? item.success ?? 0),
        failed: Number(item.failed ?? 0),
        skipped: Number(item.skipped ?? 0),
        tags: Array.isArray(item.tags) ? item.tags.join(", ") : String(item.tags || "-"),
      }));

      const fallbackRowsFromChecks = (baseRowsFromReport.length ? [] : activeChecks).map((check, idx) => {
        const status = normalizeStatus(check.status);
        return {
          id: `cucumber-fallback-${idx}`,
          feature: check.name || check.id || "N/A",
          scenarios: 1,
          passed: status === "passed" ? 1 : 0,
          failed: status === "failed" ? 1 : 0,
          skipped: status === "skipped" ? 1 : 0,
          tags: check.severity ? String(check.severity) : "-",
        };
      });

      const baseRows = baseRowsFromReport.length ? baseRowsFromReport : fallbackRowsFromChecks;

      const rows = baseRows.filter((row) => {
        if (!q) return true;
        return `${row.feature} ${row.tags}`.toLowerCase().includes(q);
      });

      return {
        title: "Cucumber Report",
        columns: ["Feature", "Scenarios", "Passed", "Failed", "Skipped", "Tags"],
        rows,
      };
    }

    if (reportView === "api-inventory") {
      const baseRows = (activeApis || []).map((api, idx) => ({
        id: `api-inv-${idx}-${api.method || "m"}-${api.path || "p"}`,
        method: api.method ? String(api.method).toUpperCase() : "N/A",
        path: formatPath(api.path),
        file: api.file || "N/A",
        line: api.line != null && api.line !== "" ? String(api.line) : "N/A",
        secure: api.secure === true ? "Secure" : api.secure === false ? "Vulnerable" : "N/A",
        secureFlag: api.secure,
        payloadViolations:
          api.payloadViolationCount != null ? String(api.payloadViolationCount) : "0",
        description: api.description || api.summary || "N/A",
      }));

      const rows = baseRows.filter((row) => {
        if (!q) return true;
        return `${row.method} ${row.path} ${row.file} ${row.line} ${row.secure} ${row.description}`
          .toLowerCase()
          .includes(q);
      });

      return {
        title: "API Inventory",
        columns: ["Method", "Endpoint", "File", "Line", "Status", "Payload Issues"],
        rows,
      };
    }

    if (reportView === "relationship-api") {
      const rel = specInsights.relationsBetweenApi || {};
      const edges =
        Array.isArray(rel)
          ? rel
          : Array.isArray(rel.edges)
            ? rel.edges
            : Array.isArray(rel.apiLinks)
              ? rel.apiLinks
              : Array.isArray(rel.api_links)
                ? rel.api_links
                : Array.isArray(rel.relationships)
                  ? rel.relationships
                  : [];

      const baseRowsFromEdges = edges.map((edge, idx) => ({
        id: `rel-${idx}`,
        from: edge.from || edge.source || "N/A",
        to: edge.to || edge.target || "N/A",
        type: edge.type || edge.relation || "N/A",
        via: edge.via || edge.file || "-",
      }));

      const fallbackRowsFromApis = (baseRowsFromEdges.length ? [] : activeApis).map((api, idx) => ({
        id: `rel-fallback-${idx}`,
        from: formatEndpoint(api.method, api.path),
        to: api.file || "spec-file",
        type: "defined-in",
        via: api.line ? `${api.file || "spec-file"}:${api.line}` : (api.file || "spec-file"),
      }));

      const baseRows = baseRowsFromEdges.length ? baseRowsFromEdges : fallbackRowsFromApis;

      const rows = baseRows.filter((row) => {
        if (!q) return true;
        return `${row.from} ${row.to} ${row.type} ${row.via}`.toLowerCase().includes(q);
      });

      return {
        title: "Relationship API",
        columns: ["From", "To", "Type", "Via"],
        rows,
      };
    }

    if (reportView === "cucumber-compare") {
      const diff = specInsights.difference || {};
      const issues = diff.issues || diff.issue_summary || {};
      const cucumber = diff.cucumber || diff.cucumber_report || {};
      const fixed = Array.isArray(issues.fixed) ? issues.fixed : [];
      const pending = Array.isArray(issues.pending) ? issues.pending : [];
      const regressed = Array.isArray(cucumber.regressed) ? cucumber.regressed : [];

      const baseRows = [
        ...fixed.map((item, idx) => ({
          id: `cmp-fixed-${idx}`,
          status: "Fixed",
          type: item.type || "N/A",
          scenario: item.scenarioName || item.scenarioId || item.name || "N/A",
          message: item.message || "-",
        })),
        ...pending.map((item, idx) => ({
          id: `cmp-pending-${idx}`,
          status: "Pending",
          type: item.type || "N/A",
          scenario: item.scenarioName || item.scenarioId || item.name || "N/A",
          message: item.message || "-",
        })),
        ...regressed.map((item, idx) => ({
          id: `cmp-regressed-${idx}`,
          status: "Regressed",
          type: "CUCUMBER",
          scenario: typeof item === "string" ? item : (item?.scenarioName || item?.scenarioId || "N/A"),
          message: typeof item === "string" ? "Regressed in current scan" : (item?.message || "Regressed in current scan"),
        })),
      ];

      const rows = baseRows.filter((row) => {
        if (!q) return true;
        return `${row.status} ${row.type} ${row.scenario} ${row.message}`.toLowerCase().includes(q);
      });

      return {
        title: "Cucumber Compare Old vs Previous",
        columns: ["Status", "Type", "Scenario", "Message"],
        rows,
      };
    }

    return {
      title: "API Discovery Findings",
      columns: [],
      rows: [],
    };
  }, [query, reportView, specInsights, activeChecks, activeApis]);

  useEffect(() => {
    setCurrentPage(1);
  }, [query, selectedSeverities, selectedRules, filteredFindingsRows.length, nonFindingsConfig.rows.length, reportView]);

  const tableRows = isFindingsView ? filteredFindingsRows : nonFindingsConfig.rows;
  const totalPages = Math.max(1, Math.ceil(tableRows.length / pageSize));
  const safePage = Math.min(currentPage, totalPages);
  const pageStart = (safePage - 1) * pageSize;
  const pageEnd = Math.min(pageStart + pageSize, tableRows.length);
  const pageRows = tableRows.slice(pageStart, pageEnd);

  useInteractiveTable({
    containerRef: tableRef,
    storageKey: `scanops-spec-scanner-table-${reportView}`,
    minWidth: 88,
    deps: [reportView, pageRows.length, safePage, pageSize, query, selectedSeverities, selectedRules],
  });

  const goToPage = (page) => setCurrentPage(clamp(page, 1, totalPages));

  const toSidebarFinding = (row) => {
    const lineFromRow = Number(row.line);
    let lineNo =
      Number.isFinite(lineFromRow) && lineFromRow > 0 ? lineFromRow : undefined;
    if (!lineNo) {
      const [, linePart] = String(row.location || "").split(":");
      const parsedLine = Number(linePart);
      if (Number.isFinite(parsedLine) && parsedLine > 0) lineNo = parsedLine;
    }

    // Prefer explicit source file; never treat an API path ("/api/…") as a file.
    let file = row.file || null;
    if (!file && row.location) {
      const [filePart] = String(row.location).split(":");
      if (filePart && !filePart.startsWith("/")) {
        file = filePart;
      }
    }
    file = file || "N/A";

    const category = row.category || getCategoryFromRule(row.rule, row.message);
    const examples = getSpecRemediationExamples({
      rule: row.rule,
      category,
      method: row.method,
      endpoint: row.endpoint,
      file,
    });
    const capturedCodeBlock = row.codeBlock || null;
    const codeBlock =
      capturedCodeBlock ||
      buildSpecSourceContext({
        file,
        line: lineNo,
        method: row.method,
        endpoint: row.endpoint,
        message: row.message,
        category,
      });

    return {
      policyCode: row.rule || "N/A",
      title: row.message || row.rule || "Spec scanner finding",
      description: row.message || "N/A",
      severity: row.severity || "medium",
      type: row.type || "spec-scanner",
      category,
      provider: "spec-scanner",
      checkerKey: row.type || "SPEC",
      mappedIdentifier: row.rule || "N/A",
      file,
      fullPath: file,
      lineNo,
      codeBlock,
      codeBlockCaptured: Boolean(capturedCodeBlock),
      examples,
      remediation:
        examples
          ? "Review the vulnerable pattern below and apply the required OWASP/API security control on this endpoint."
          : "Review the endpoint contract and apply the required OWASP/API security control.",
      endpoint: row.endpoint,
      method: row.method,
      payload: row.payload || null,
      payloadViolations: Array.isArray(row.payloadViolations) ? row.payloadViolations : [],
    };
  };

  const handleFindingClick = (row) => {
    setSelectedFinding(toSidebarFinding(row));
    setIsSidebarOpen(true);
  };

  const handleCloseSidebar = () => {
    setIsSidebarOpen(false);
    setTimeout(() => setSelectedFinding(null), 300);
  };

  useEffect(() => {
    document.body.style.overflow = isSidebarOpen ? "hidden" : "auto";
    return () => {
      document.body.style.overflow = "auto";
    };
  }, [isSidebarOpen]);

  const hasFilters = isFindingsView
    ? query.trim() !== "" || !hasAllSeverities || !hasAllRules
    : query.trim() !== "";

  const clearFilters = () => {
    setQuery("");
    if (isFindingsView) {
      setSelectedSeverities(SEVERITY_ORDER);
      setSelectedRules(null);
      setCurrentPage(1);
    }
  };

  const scanMetadata = useDummy ? DUMMY_DATA.scanMetadata : (latestScan?.scan_metadata || {});
  const metadataCards = [
    {
      label: "Repository",
      value: [scanMetadata.organization, scanMetadata.repository].filter(Boolean).join("/") || "N/A",
      icon: GitCommitHorizontal,
    },
    {
      label: "Commit Author",
      value: String(scanMetadata.commit_author || "").trim() || "N/A",
      icon: User,
    },
    {
      label: "Branch",
      value: scanMetadata.branch || "N/A",
      icon: GitBranch,
    },
    {
      label: "Scan Date",
      value: formatDate(scanMetadata.scan_timestamp || latestCreatedAt),
      icon: Calendar,
    },
  ];

  const totalViolations = useDummy ? DUMMY_DATA.totalViolations : Number(specMeta.totalViolations || activeFindingsRows.length || 0);
  const totalApis = useDummy ? DUMMY_DATA.totalApis : Number(specMeta.totalApis || apis.length || 0);
  const vulnerableApis = useDummy ? DUMMY_DATA.vulnerableApis : Number(specMeta.vulnerableApis || apis.filter((api) => !api.secure).length || 0);
  const checksFailed = useDummy
    ? DUMMY_DATA.checksFailed
    : Number(specMeta.failed || checks.filter((check) => normalizeStatus(check.status) === "failed").length || 0);

  const summaryCards = [
    { title: "APIs Scanned", value: totalApis, color: "#3B82F6", icon: Link2 },
    { title: "Total Violations", value: totalViolations, color: "#F59E0B", icon: AlertTriangle },
    { title: "Failed Checks", value: checksFailed, color: "#EF4444", icon: AlertCircle },
    { title: "Vulnerable APIs", value: vulnerableApis, color: "#06B6D4", icon: ShieldCheck },
  ];

  if (loading) {
    return (
      <div className="flex h-full min-h-[350px] items-center justify-center p-8">
        <div className="text-center p-6 max-w-md flex flex-col items-center gap-3">
          <ShieldCheck className="w-12 h-12 text-primary mx-auto mb-2 animate-pulse" />
          <h2 className="text-lg font-semibold text-[var(--text)]">Loading API Discovery Data</h2>
          <p className="text-sm text-[var(--muted)]">Fetching latest scan results...</p>
        </div>
      </div>
    );
  }

  const isNoApiDiscoveredMessage = (value) => {
    const msg = String(value || "").toLowerCase();
    return (
      msg.includes("no api paths could be extracted") ||
      msg.includes("no api discovered")
    );
  };

  const isNoScanError = (value) => {
    const msg = String(value || "").toLowerCase();
    return (
      msg.includes("no scans found") ||
      msg.includes("no scan found") ||
      msg.includes("scan not found")
    );
  };

  const isUninitiatedScan =
    (hasScanError && isNoScanError(error)) ||
    (!latestScan && !loading);

  const scanUnavailableMessage = hasScanError
    ? (isNoScanError(error)
      ? "Scan Not Initiated"
      : isNoApiDiscoveredMessage(error)
        ? "No API Discovered"
        : `Unable to load API Discovery results: ${error}`)
    : (!latestScan && !loading)
      ? "Scan Not Initiated"
      : "";

  const specScannerNotRun = !activeFindingsRows.length && !activeChecks.length && !activeApis.length && !specInsights.hasAny;
  const specScannerError = String(scannerNode?.error || "").trim();
  const noApiDiscovered =
    Boolean(scannerNode?.metadata?.no_api_discovered) ||
    isNoApiDiscoveredMessage(specScannerError) ||
    isNoApiDiscoveredMessage(error);

  const noDataMessage = isUninitiatedScan
    ? "Start a new scan to find issues."
    : scanUnavailableMessage || (specScannerNotRun
      ? (noApiDiscovered
        ? "No API Discovered"
        : specScannerError
          ? `API Discovery failed: ${specScannerError}`
          : "No API specification results were produced for this repository. Run a spec scan after adding a valid OpenAPI/Swagger file.")
      : "");

  if (noDataMessage || isUninitiatedScan) {
    return (
      <EmptyState
        title={
          isUninitiatedScan
            ? "Scan Not Initiated"
            : noApiDiscovered || noDataMessage === "No API Discovered"
              ? "No API Discovered"
              : undefined
        }
        message={
          isUninitiatedScan
            ? "Start a new scan to find issues."
            : noApiDiscovered || noDataMessage === "No API Discovered"
              ? "No API paths could be extracted from this repository. Add an OpenAPI/Swagger spec or API routes, then run a scan again."
              : noDataMessage
        }
      />
    );
  }

  return (
    <>
      <PolicyDetailsSidebar
        finding={selectedFinding}
        repositoryContext={{
          installationId:
            selectedInstallation?.installationId || latestScan?.installation_id,
          repository: `${scanMetadata.organization || scanMetadata.org_name || ""}/${scanMetadata.repository || scanMetadata.repo_name || ""}`,
          branch: scanMetadata.branch || "main",
        }}
        isOpen={isSidebarOpen}
        onClose={handleCloseSidebar}
      />

      <div className={`transition-opacity duration-300 ${isSidebarOpen ? "pointer-events-none opacity-40" : "pointer-events-auto opacity-100"} ${styles.pageRoot}`}>
        <main className={styles.contentWrap}>

          <ScanMetadataOverview
            scanMetadata={scanMetadata}
            scanType="API Discovery"
            title="API Discovery Security Analysis"
            duration={formatDate(scanMetadata.scan_timestamp || latestCreatedAt)}
          />

          <section className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-6 items-stretch">
            <SecurityScoreCard score={score} />
            <IssuesBySeverityCard severityCounts={severityCounts} />

            <div
              className="rounded-2xl border border-[var(--border)] bg-[var(--surface)] p-6 shadow-2 flex flex-col justify-between items-stretch hover:translate-y-[-2px] hover:shadow-xl transition-all duration-300"
              style={{ minHeight: "280px" }}
            >
              <div className="flex items-center justify-between gap-2 mb-2">
                <h4
                  style={{
                    fontFamily: "var(--font-ui)",
                    fontWeight: 700,
                    fontSize: "11px",
                    lineHeight: "16px",
                    letterSpacing: "0.08em",
                    textTransform: "uppercase",
                    color: "var(--muted)",
                    margin: 0,
                  }}
                >
                  Check Results
                </h4>
                {checkStatusData.length > 0 && (
                  <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-semibold text-[var(--muted)] bg-[var(--elevated-surface)] border border-[var(--border)]">
                    <span>Checks:</span>
                    <strong className="text-[var(--text)] font-bold">{checkStatusData.length}</strong>
                  </span>
                )}
              </div>

              {checkStatusData.length > 0 ? (
                <div className="flex flex-row items-center justify-between gap-6 w-full flex-grow overflow-hidden py-1">
                  <div className="w-[160px] h-[160px] shrink-0 flex items-center justify-center">
                    <PieChartUI
                      data={checkStatusData}
                      height={160}
                      innerRadius={50}
                      outerRadius={75}
                      showLegend={false}
                      showCenterText={false}
                    />
                  </div>

                  <div className="flex flex-col gap-2 flex-grow min-w-0 max-h-[180px] overflow-y-auto pr-1">
                    {checkStatusData.map((item, idx) => (
                      <div
                        key={`${item.name}-${idx}`}
                        className="flex items-center justify-between w-full px-2 py-1 rounded-lg hover:bg-[var(--elevated-surface)]/60 transition-colors"
                      >
                        <div className="flex items-center gap-2.5 min-w-0">
                          <span
                            className="w-2.5 h-2.5 rounded-full shrink-0"
                            style={{
                              backgroundColor: item.color,
                              boxShadow: `0px 0px 8px ${item.color}80`,
                            }}
                          />
                          <span
                            className="font-semibold text-xs text-[var(--text)] whitespace-nowrap overflow-hidden text-ellipsis"
                            title={item.name}
                          >
                            {item.name}:
                          </span>
                        </div>
                        <span className="font-bold text-sm text-[var(--text)] shrink-0 ml-3">
                          {item.value}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              ) : (
                <div className="flex flex-col items-center justify-center flex-grow py-8 text-muted text-xs">
                  No check result data available
                </div>
              )}
            </div>
          </section>

          <section className="rounded-2xl border border-default bg-surface shadow-1 overflow-hidden">
            {/* Figma Table Header Area */}
            <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 p-6 border-b border-default">
              <div>
                <h2 className="text-sm font-semibold tracking-wider uppercase text-text">
                  {isFindingsView ? "API DISCOVERY FINDINGS" : nonFindingsConfig.title.toUpperCase()}
                </h2>
                <p className="mt-1 text-xs text-muted">
                  Showing {tableRows.length > 0 ? `${pageStart + 1}–${pageEnd}` : "0"} of {tableRows.length} results
                  {isFindingsView ? ` from ${activeFindingsRows.length} total` : ""}
                </p>
              </div>

              <div className="flex flex-wrap items-center gap-3">
                <div className="relative flex items-center rounded-md border border-default bg-surface px-3 py-1.5 min-w-[220px] max-w-full">
                  <Search className="h-3.5 w-3.5 text-muted shrink-0 mr-2" />
                  <input
                    type="text"
                    value={query}
                    onChange={(e) => {
                      setQuery(e.target.value);
                      setCurrentPage(1);
                    }}
                    placeholder="Search rule, endpoint, or message..."
                    className="w-full bg-transparent text-xs text-text outline-none placeholder:text-muted"
                  />
                </div>

                <div className="relative inline-flex items-center rounded-md border border-default bg-surface px-3 py-1.5">
                  <FileText className="h-3.5 w-3.5 text-muted mr-2 shrink-0" />
                  <select
                    aria-label="Select report view"
                    value={reportView}
                    onChange={(event) => setReportView(event.target.value)}
                    className="bg-transparent text-xs font-medium text-text outline-none cursor-pointer pr-4"
                  >
                    <option value="spec-findings">API Discovery Findings</option>
                    <option value="api-inventory">API Inventory</option>
                    <option value="cucumber-report">Cucumber Report</option>
                    <option value="relationship-api">Relationship API</option>
                    <option value="cucumber-compare">Cucumber Compare Old vs Previous</option>
                  </select>
                </div>
              </div>
            </div>

            {/* Filter Pills Bar */}
            {isFindingsView ? (
              <div className="flex flex-wrap items-center gap-3 px-6 py-3.5 border-b border-default bg-surface">
                <span className="text-xs font-medium uppercase tracking-wider text-muted mr-1">
                  FILTERS
                </span>

                {/* Severity Filter Dropdown */}
                <div className="relative spec-severity-dropdown">
                  <button
                    type="button"
                    onClick={() => {
                      setSeverityDropdownOpen((v) => !v);
                      setRuleDropdownOpen(false);
                      setPageSizeDropdownOpen(false);
                    }}
                    className={`inline-flex items-center gap-2 rounded-lg border px-3.5 py-1.5 text-xs font-normal transition-colors shadow-sm ${hasPartialSeverity
                        ? "border-primary/40 bg-primary/10 text-primary font-medium"
                        : "border-default bg-surface text-muted hover:border-hover hover:text-text"
                      }`}
                  >
                    <span>
                      Severity:{" "}
                      <strong className="font-medium text-text">
                        {hasPartialSeverity ? `(${selectedSeverities.length})` : hasAllSeverities ? "All" : "(0)"}
                      </strong>
                    </span>
                    <ChevronDown className={`h-3.5 w-3.5 text-muted transition-transform ${severityDropdownOpen ? "rotate-180" : ""}`} />
                  </button>

                  {severityDropdownOpen && (
                    <div className="absolute left-0 top-full mt-1.5 w-52 rounded-xl border border-default bg-surface shadow-lg z-50 py-1 overflow-hidden">
                      <div className="flex items-center justify-between border-b border-default bg-surface px-3.5 py-2">
                        <button
                          type="button"
                          onClick={selectAllSeverities}
                          className="text-xs text-primary hover:underline font-medium"
                        >
                          Select All
                        </button>
                        <button
                          type="button"
                          onClick={clearAllSeverities}
                          className="text-xs text-muted hover:text-text"
                        >
                          Clear
                        </button>
                      </div>
                      {SEVERITY_ORDER.map((level) => {
                        const dotColor = SEVERITY_FIGMA_COLORS[level]?.dot || "#999";
                        return (
                          <label
                            key={level}
                            className="group flex cursor-pointer items-center justify-between px-3.5 py-2 text-xs hover:bg-elevated text-left text-text transition-colors"
                          >
                            <span className="flex items-center gap-2">
                              <span className="h-2 w-2 rounded-full" style={{ backgroundColor: dotColor }} />
                              <span className="capitalize">{formatApiText(level)}</span>
                            </span>
                            <input
                              type="checkbox"
                              checked={selectedSeverities.includes(level)}
                              onChange={() => toggleSeverity(level)}
                              className="h-3.5 w-3.5 rounded border-default bg-surface text-primary focus:ring-1 focus:ring-primary/30"
                            />
                          </label>
                        );
                      })}
                    </div>
                  )}
                </div>

                {/* Rule / Control Filter Dropdown */}
                <div className="relative spec-rule-dropdown">
                  <button
                    type="button"
                    onClick={() => {
                      setRuleDropdownOpen((v) => !v);
                      setSeverityDropdownOpen(false);
                      setPageSizeDropdownOpen(false);
                    }}
                    className={`inline-flex items-center gap-2 rounded-lg border px-3.5 py-1.5 text-xs font-normal transition-colors shadow-sm ${hasPartialRules
                        ? "border-primary/40 bg-primary/10 text-primary font-medium"
                        : "border-default bg-surface text-muted hover:border-hover hover:text-text"
                      }`}
                  >
                    <span>
                      Control:{" "}
                      <strong className="font-medium text-text">
                        {hasPartialRules ? `(${selectedRules.length})` : hasAllRules ? "All" : "(0)"}
                      </strong>
                    </span>
                    <ChevronDown className={`h-3.5 w-3.5 text-muted transition-transform ${ruleDropdownOpen ? "rotate-180" : ""}`} />
                  </button>

                  {ruleDropdownOpen && (
                    <div className="absolute left-0 top-full mt-1.5 w-60 max-h-60 overflow-y-auto rounded-xl border border-default bg-surface shadow-lg z-50 py-1">
                      <div className="flex items-center justify-between border-b border-default bg-surface px-3.5 py-2">
                        <button
                          type="button"
                          onClick={selectAllRules}
                          className="text-xs text-primary hover:underline font-medium"
                        >
                          Select All
                        </button>
                        <button
                          type="button"
                          onClick={clearAllRules}
                          className="text-xs text-muted hover:text-text"
                        >
                          Clear
                        </button>
                      </div>
                      {ruleOptions.map((rule) => (
                        <label
                          key={rule}
                          className="group flex cursor-pointer items-center justify-between px-3.5 py-2 text-xs hover:bg-elevated text-left text-text transition-colors"
                        >
                          <span className="truncate">{rule}</span>
                          <input
                            type="checkbox"
                            checked={(selectedRules ?? ruleOptions).includes(rule)}
                            onChange={() => toggleRule(rule)}
                            className="h-3.5 w-3.5 rounded border-default bg-surface text-primary focus:ring-1 focus:ring-primary/30 shrink-0 ml-2"
                          />
                        </label>
                      ))}
                    </div>
                  )}
                </div>

                {hasFilters && (
                  <button
                    type="button"
                    onClick={clearFilters}
                    className="inline-flex items-center gap-1 rounded-lg border border-default px-2.5 py-1.5 text-xs text-muted hover:bg-elevated hover:text-text transition-colors"
                  >
                    <X className="h-3.5 w-3.5" />
                    <span>Clear</span>
                  </button>
                )}
              </div>
            ) : (
              <div className="flex items-center justify-end gap-2 px-6 py-3 border-b border-default bg-surface">
                {hasFilters && (
                  <button
                    type="button"
                    onClick={clearFilters}
                    className="inline-flex items-center gap-1 rounded-lg border border-default px-3 py-1.5 text-xs text-muted hover:bg-elevated transition-colors"
                  >
                    <X className="h-3.5 w-3.5" />
                    Clear Search
                  </button>
                )}
              </div>
            )}

            {/* Table Area */}
            <div className="overflow-x-auto scrollbar-hide-lg" ref={tableRef}>
              {isFindingsView ? (
                <table className="w-full min-w-[1240px] table-fixed">
                  <colgroup>
                    <col style={{ width: "12%" }} />{/* Violation ID */}
                    <col style={{ width: "10%" }} />{/* Severity */}
                    <col style={{ width: "12%" }} />{/* Category */}
                    <col style={{ width: "8%" }} />{/* Protocol */}
                    <col style={{ width: "7%" }} />{/* Method */}
                    <col style={{ width: "17%" }} />{/* Endpoint */}
                    <col style={{ width: "26%" }} />{/* Message */}
                    <col style={{ width: "8%" }} />{/* Action */}
                  </colgroup>
                  <thead className="border-b border-default figma-table-head bg-[var(--table-head-bg)]">
                    <tr>
                      <th className="px-6 py-3.5 text-center text-xs font-semibold text-text">Violation ID</th>
                      <th className="px-4 py-3.5 text-center text-xs font-semibold text-text">Severity</th>
                      <th className="px-4 py-3.5 text-center text-xs font-semibold text-text">Category</th>
                      <th className="px-4 py-3.5 text-center text-xs font-semibold text-text">Protocol</th>
                      <th className="px-4 py-3.5 text-center text-xs font-semibold text-text">Method</th>
                      <th className="px-4 py-3.5 text-center text-xs font-semibold text-text">Endpoint</th>
                      <th className="px-4 py-3.5 text-center text-xs font-semibold text-text">Message</th>
                      <th className="px-6 py-3.5 text-center text-xs font-semibold text-text">Action</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-default">
                    {pageRows.length ? (
                      pageRows.map((row) => (
                        <tr key={row.id} className="group transition-colors hover:bg-elevated/40 border-b border-default">
                          <td className="px-6 py-3.5 align-middle text-left">
                            <span className="block font-mono text-xs font-bold text-[var(--text)] truncate text-left" title={row.rule}>
                              {row.rule}
                            </span>
                          </td>
                          <td className="px-4 py-3.5 align-middle text-left">
                            <TableSeverityBadge severity={row.severity} />
                          </td>
                          <td className="px-4 py-3.5 align-middle text-left">
                            <span className="text-xs uppercase text-[var(--text)] font-semibold truncate block text-left" title={row.category || getCategoryFromRule(row.rule, row.message)}>
                              {row.category || getCategoryFromRule(row.rule, row.message)}
                            </span>
                          </td>
                          <td className="px-4 py-3.5 align-middle text-left">
                            <span className="text-xs uppercase text-[var(--text)] font-semibold text-left">
                              {getProtocolFromRow(row)}
                            </span>
                          </td>
                          <td className="px-4 py-3.5 align-middle text-left">
                            <span className="text-xs uppercase text-[var(--text)] font-semibold text-left">
                              {row.method || "GET"}
                            </span>
                          </td>
                          <td className="px-4 py-3.5 align-middle max-w-0 text-left">
                            <span className="block truncate font-mono text-xs font-bold text-[var(--text)] text-left" title={row.endpoint}>
                              {row.endpoint}
                            </span>
                          </td>
                          <td className="px-4 py-3.5 align-middle text-left">
                            <span
                              className="block break-words line-clamp-2 text-xs font-medium leading-relaxed text-[var(--text)] text-left"
                              title={row.message}
                            >
                              {row.message}
                            </span>
                          </td>
                          <td className="px-6 py-3.5 align-middle text-left">
                            <button
                              type="button"
                              onClick={(event) => {
                                event.stopPropagation();
                                handleFindingClick(row);
                              }}
                              aria-label="View details"
                              className="inline-flex items-center gap-1 text-xs font-medium text-text hover:text-primary transition-colors whitespace-nowrap"
                              title="Expand finding details"
                            >
                              <span>Expand</span>
                              <ChevronRight className="h-3.5 w-3.5" />
                            </button>
                          </td>
                        </tr>
                      ))
                    ) : (
                      <tr>
                        <td colSpan="8" className="px-4 py-14 text-left text-muted">
                          <div className="flex flex-col items-center gap-2">
                            <FileText className="w-8 h-8 text-muted/50" />
                            <p className="text-sm">No findings match your filter criteria</p>
                          </div>
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              ) : (
                nonFindingsConfig.rows.length === 0 ? (
                  <div className="flex flex-col items-center justify-center gap-3 py-20 text-center">
                    <FileText className="w-10 h-10 text-muted/40" />
                    <p className="text-sm font-medium text-muted">
                      {reportView === "api-inventory" && "No API inventory endpoints were returned for this scan."}
                      {reportView === "relationship-api" && "No API relationships detected for this scan."}
                      {reportView === "cucumber-report" && "No Cucumber report data available for this scan."}
                      {reportView === "cucumber-compare" && "No comparison data available. Run another scan to see differences."}
                      {!["api-inventory", "relationship-api", "cucumber-report", "cucumber-compare"].includes(reportView) && "No data available for this report."}
                    </p>
                  </div>
                ) : (
                  <table className="w-full min-w-[920px] table-fixed">
                    <thead className="border-b border-default figma-table-head bg-[var(--table-head-bg)]">
                      <tr>
                        {nonFindingsConfig.columns.map((column) => (
                          <th key={column} className="px-4 py-3.5 text-center text-xs font-semibold text-text">
                            {column}
                          </th>
                        ))}
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-default">
                      {pageRows.map((row) => (
                        <tr key={row.id} className="transition-colors hover:bg-elevated/40 border-b border-default">
                          {reportView === "cucumber-report" && (
                            <>
                              <td className="px-4 py-3.5 text-[12px] text-text text-left">{row.feature}</td>
                              <td className="px-4 py-3.5 text-[12px] text-muted text-left">{row.scenarios}</td>
                              <td className="px-4 py-3.5 text-[12px] text-[var(--success)] font-semibold text-left">{row.passed}</td>
                              <td className="px-4 py-3.5 text-[12px] text-[var(--danger)] font-semibold text-left">{row.failed}</td>
                              <td className="px-4 py-3.5 text-[12px] text-muted text-left">{row.skipped}</td>
                              <td className="px-4 py-3.5 text-[12px] text-muted text-left">{row.tags}</td>
                            </>
                          )}
                          {reportView === "api-inventory" && (
                            <>
                              <td className="overflow-hidden px-4 py-3.5 align-top text-left">
                                <span className="inline-flex items-center justify-start rounded-md border px-2 py-0.5 text-[10px] font-bold uppercase" style={{ color: "var(--text)", borderColor: "var(--border)", background: "var(--elevated-surface)" }}>
                                  {row.method}
                                </span>
                              </td>
                              <td className="max-w-0 overflow-hidden px-4 py-3.5 align-top text-left">
                                <span className="block truncate font-mono text-[12px] font-bold text-[var(--text)] text-left" title={row.path}>{row.path}</span>
                              </td>
                              <td className="max-w-0 overflow-hidden px-4 py-3.5 align-top text-left">
                                <span className="block truncate font-mono text-[12px] font-semibold text-[var(--text)] text-left" title={row.file}>{row.file}</span>
                              </td>
                              <td className="overflow-hidden px-4 py-3.5 align-top text-left">
                                <span className="font-mono text-[12px] font-semibold text-[var(--text)] text-left">{row.line}</span>
                              </td>
                              <td className="overflow-hidden px-4 py-3.5 align-top text-left">
                                <span
                                  className="inline-flex items-center justify-start rounded-md border px-2 py-0.5 text-[10px] font-semibold"
                                  style={{
                                    color: row.secureFlag === false ? "var(--danger)" : row.secureFlag === true ? "var(--success)" : "var(--muted)",
                                    borderColor: row.secureFlag === false ? "rgba(239,68,68,0.35)" : row.secureFlag === true ? "rgba(34,197,94,0.35)" : "var(--border)",
                                    background: row.secureFlag === false ? "rgba(239,68,68,0.08)" : row.secureFlag === true ? "rgba(34,197,94,0.08)" : "var(--elevated-surface)",
                                  }}
                                >
                                  {row.secure}
                                </span>
                              </td>
                              <td className="overflow-hidden px-4 py-3.5 align-top text-left">
                                <span className="text-[12px] text-muted text-left">{row.payloadViolations}</span>
                              </td>
                            </>
                          )}
                          {reportView === "relationship-api" && (
                            <>
                              <td className="px-4 py-3.5 font-mono text-[12px] text-text text-left">{row.from}</td>
                              <td className="px-4 py-3.5 font-mono text-[12px] text-text text-left">{row.to}</td>
                              <td className="px-4 py-3.5 text-[12px] text-text text-left">{row.type}</td>
                              <td className="px-4 py-3.5 font-mono text-[12px] text-muted text-left">{row.via}</td>
                            </>
                          )}
                          {reportView === "cucumber-compare" && (
                            <>
                              <td className="px-4 py-3.5 text-[12px] font-semibold text-text text-left">{row.status}</td>
                              <td className="px-4 py-3.5 text-[12px] text-muted text-left">{row.type}</td>
                              <td className="px-4 py-3.5 text-[12px] text-text text-left">{row.scenario}</td>
                              <td className="px-4 py-3.5 text-[12px] text-muted text-left">{row.message}</td>
                            </>
                          )}
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )
              )}
            </div>

            {/* Pagination Footer */}
            {tableRows.length > 0 && (
              <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 p-6 border-t border-default bg-surface">
                <div className="relative spec-pagesize-dropdown">
                  <button
                    type="button"
                    onClick={() => setPageSizeDropdownOpen((v) => !v)}
                    className="inline-flex items-center gap-2 rounded-lg border border-default bg-surface px-3 py-1.5 text-xs text-text hover:border-hover hover:bg-elevated transition-colors shadow-sm"
                  >
                    <span>Show: {pageSize} rows</span>
                    <ChevronDown className={`h-3.5 w-3.5 text-muted transition-transform ${pageSizeDropdownOpen ? "rotate-180" : ""}`} />
                  </button>

                  {pageSizeDropdownOpen && (
                    <div className="absolute left-0 bottom-full mb-1.5 w-32 rounded-lg border border-default bg-surface shadow-xl z-50 py-1 overflow-hidden">
                      {PAGE_SIZE_OPTIONS.map((size) => (
                        <button
                          key={size}
                          type="button"
                          onClick={() => {
                            setPageSize(size);
                            setCurrentPage(1);
                            setPageSizeDropdownOpen(false);
                          }}
                          className="w-full flex items-center justify-between px-3.5 py-2 text-xs hover:bg-elevated text-left text-text transition-colors"
                        >
                          <span>{size}</span>
                          {pageSize === size && <Check className="h-3.5 w-3.5 text-primary" />}
                        </button>
                      ))}
                    </div>
                  )}
                </div>

                <div className="flex items-center gap-1.5">
                  <button
                    type="button"
                    onClick={() => goToPage(safePage - 1)}
                    disabled={safePage === 1}
                    aria-label="Previous page"
                    className="inline-flex h-8 w-8 items-center justify-center rounded-lg border border-default bg-surface text-text hover:bg-elevated disabled:opacity-30 disabled:pointer-events-none transition-colors"
                  >
                    <ChevronLeft className="h-4 w-4" />
                  </button>

                  {getPaginationPages(safePage, totalPages).map((page, idx) =>
                    page === "..." ? (
                      <span key={`ellipsis-${idx}`} className="inline-flex h-8 w-8 items-center justify-center text-xs text-muted">...</span>
                    ) : (
                      <button
                        key={page}
                        type="button"
                        onClick={() => goToPage(page)}
                        className={`inline-flex h-8 w-8 items-center justify-center rounded-lg text-xs font-medium transition-colors border ${safePage === page
                            ? "border-primary/70 bg-elevated font-semibold text-primary"
                            : "border-default bg-surface text-muted hover:bg-elevated hover:text-text"
                          }`}
                      >
                        {page}
                      </button>
                    )
                  )}

                  <button
                    type="button"
                    onClick={() => goToPage(safePage + 1)}
                    disabled={safePage === totalPages}
                    aria-label="Next page"
                    className="inline-flex h-8 w-8 items-center justify-center rounded-lg border border-default bg-surface text-text hover:bg-elevated disabled:opacity-30 disabled:pointer-events-none transition-colors"
                  >
                    <ChevronRight className="h-4 w-4" />
                  </button>
                </div>
              </div>
            )}
          </section>

          {/* API Relations & Scan Difference */}
          <section className="grid grid-cols-1 xl:grid-cols-2 gap-6">

            {/* ── API Relations ── */}
            <article className={styles.panelCard}>
              <div className="mb-3 flex items-center justify-between gap-2">
                <h3 className="!mb-0">API Relations</h3>
                <span className="inline-flex h-7 w-7 items-center justify-center rounded-md border border-default bg-elevated/30 text-primary">
                  <Link2 className="h-3.5 w-3.5" />
                </span>
              </div>

              {(() => {
                const rel = specInsights.relationsBetweenApi;
                if (!rel) return (
                  <div className={styles.chartLoading}>
                    No relation data available
                  </div>
                );
                const edges = Array.isArray(rel.edges) ? rel.edges : Array.isArray(rel.apiLinks) ? rel.apiLinks : [];
                const nodes = Array.isArray(rel.nodes) ? rel.nodes : [];
                const summary = rel.summary || {};
                const edgeTypeColors = {
                  "shares-file": { color: "#3b82f6", bg: "rgba(59,130,246,0.1)", border: "rgba(59,130,246,0.25)" },
                  "depends-on": { color: "#f59e0b", bg: "rgba(245,158,11,0.1)", border: "rgba(245,158,11,0.25)" },
                  "uses-identity": { color: "#a855f7", bg: "rgba(168,85,247,0.1)", border: "rgba(168,85,247,0.25)" },
                  "policy-lookup": { color: "#06b6d4", bg: "rgba(6,182,212,0.1)", border: "rgba(6,182,212,0.25)" },
                };
                return (
                  <div className="space-y-3">
                    {/* Stats row */}
                    <div className="grid grid-cols-3 gap-3">
                      {[
                        { label: "Nodes", value: summary.nodes ?? nodes.length },
                        { label: "Edges", value: summary.edges ?? edges.length },
                        { label: "Protocol", value: Object.keys(summary.protocols || {})[0] || "REST" },
                      ].map((s) => (
                        <div key={s.label} className="rounded-lg border border-default bg-elevated/20 px-2.5 py-2 text-center">
                          <p className="text-sm font-bold text-text">{s.value}</p>
                          <p className="text-[10px] text-muted uppercase tracking-wide mt-0.5">{s.label}</p>
                        </div>
                      ))}
                    </div>

                    {/* Edge type legend */}
                    {summary.edgeTypes && (
                      <div className="flex flex-wrap gap-1.5">
                        {Object.entries(summary.edgeTypes).map(([type, count]) => {
                          const c = edgeTypeColors[type] || { color: "var(--muted)", bg: "var(--elevated-surface)", border: "var(--border)" };
                          return (
                            <span key={type} className="inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[10px] font-semibold border"
                              style={{ color: c.color, background: c.bg, borderColor: c.border }}>
                              {type} <span className="opacity-70">× {count}</span>
                            </span>
                          );
                        })}
                      </div>
                    )}

                    {/* Edges list */}
                    <div className="space-y-2 max-h-[240px] overflow-y-auto pr-1">
                      <p className="text-[10px] font-bold text-muted uppercase tracking-widest px-0.5">Relationships</p>
                      {edges.length ? edges.map((edge, i) => {
                        const c = edgeTypeColors[edge.type] || { color: "var(--muted)", bg: "var(--elevated-surface)", border: "var(--border)" };
                        return (
                          <div key={i} className="rounded-lg border border-default bg-elevated/20 p-2.5 transition-colors hover:bg-elevated/35">
                            <div className="flex items-center gap-1.5">
                              <p className="min-w-0 flex-1 truncate font-mono text-[11px] font-semibold text-primary">{edge.from}</p>
                              <span className="text-[10px] text-muted">{"->"}</span>
                              <p className="min-w-0 flex-1 truncate font-mono text-[11px] font-semibold text-text">{edge.to}</p>
                            </div>
                            <div className="mt-1.5 flex items-center gap-2">
                              <span className="inline-flex items-center rounded-full px-2 py-0.5 text-[10px] font-semibold border"
                                style={{ color: c.color, background: c.bg, borderColor: c.border }}>
                                {edge.type}
                              </span>
                              {edge.via && <span className="truncate font-mono text-[10px] text-muted">{edge.via}</span>}
                            </div>
                          </div>
                        );
                      }) : (
                        <div className="py-6 text-center text-xs text-muted">No edges found</div>
                      )}
                    </div>
                  </div>
                );
              })()}
            </article>

            {/* ── Scan Difference ── */}
            <article className={styles.panelCard}>
              <div className="mb-3 flex items-center justify-between gap-2">
                <h3 className="!mb-0">Scan Difference</h3>
                <span className="inline-flex h-7 w-7 items-center justify-center rounded-md border border-default bg-elevated/30 text-warning">
                  <GitBranch className="h-3.5 w-3.5" />
                </span>
              </div>

              {(() => {
                const diff = specInsights.difference;
                if (!diff) return (
                  <div className={styles.chartLoading}>
                    No difference data available
                  </div>
                );
                const issues = diff.issues || {};
                const cucumber = diff.cucumber || {};
                const spec = diff.spec || {};
                const issuesSummary = issues.summary || {};
                const cucumberSummary = cucumber.summary || {};
                const specSummary = spec.summary || {};
                const pending = Array.isArray(issues.pending) ? issues.pending : [];
                const fixedList = Array.isArray(issues.fixed) ? issues.fixed : [];

                const issueCounts = [
                  { label: "Fixed", value: issuesSummary.fixed ?? fixedList.length, color: "var(--success)" },
                  { label: "Pending", value: issuesSummary.pending ?? pending.length, color: "var(--warning)" },
                  { label: "New", value: issuesSummary.new ?? 0, color: "var(--danger)" },
                ];

                return (
                  <div className="space-y-3">
                    {/* Issue counters */}
                    <div className="grid grid-cols-3 gap-3">
                      {issueCounts.map((s) => (
                        <div key={s.label} className="rounded-lg border border-default bg-elevated/20 px-2.5 py-2 text-center">
                          <p className="text-base font-bold" style={{ color: s.color }}>{s.value}</p>
                          <p className="text-[10px] text-muted uppercase tracking-wide mt-0.5">{s.label}</p>
                        </div>
                      ))}
                    </div>

                    {/* Cucumber + Spec changes side by side */}
                    <div className="grid grid-cols-2 gap-3">
                      <div className="rounded-lg border border-default bg-elevated/20 p-2.5">
                        <p className="text-[10px] font-bold text-muted uppercase tracking-widest mb-2">Cucumber</p>
                        <div className="space-y-1.5">
                          {[
                            { k: "Fixed", v: cucumberSummary.fixed ?? 0, c: "var(--success)" },
                            { k: "Regressed", v: cucumberSummary.regressed ?? 0, c: "var(--danger)" },
                            { k: "Unchanged", v: cucumberSummary.unchanged ?? 0, c: "var(--muted)" },
                            { k: "New Issues", v: cucumberSummary.newIssues ?? 0, c: "var(--warning)" },
                          ].map((r) => (
                            <div key={r.k} className="flex items-center justify-between">
                              <span className="text-[11px] text-muted">{r.k}</span>
                              <span className="text-[11px] font-bold tabular-nums" style={{ color: r.c }}>{r.v}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                      <div className="rounded-lg border border-default bg-elevated/20 p-2.5">
                        <p className="text-[10px] font-bold text-muted uppercase tracking-widest mb-2">Spec Changes</p>
                        <div className="space-y-1.5">
                          {[
                            { k: "Added", v: specSummary.added ?? 0, c: "var(--success)" },
                            { k: "Removed", v: specSummary.removed ?? 0, c: "var(--danger)" },
                            { k: "Modified", v: specSummary.modified ?? 0, c: "var(--primary)" },
                            { k: "Breaking", v: specSummary.breaking ?? 0, c: "var(--warning)" },
                          ].map((r) => (
                            <div key={r.k} className="flex items-center justify-between">
                              <span className="text-[11px] text-muted">{r.k}</span>
                              <span className="text-[11px] font-bold tabular-nums" style={{ color: r.c }}>{r.v}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    </div>

                    {/* Pending issues */}
                    {pending.length > 0 && (
                      <div className="flex flex-col gap-2">
                        <p className="text-[10px] font-bold text-muted uppercase tracking-widest">Pending Issues</p>
                        <div className="space-y-2 max-h-[190px] overflow-y-auto pr-1">
                          {pending.map((issue, i) => (
                            <div key={i} className="rounded-lg border border-default bg-elevated/20 p-2.5 transition-colors hover:bg-elevated/35"
                              style={{ borderLeft: "3px solid var(--warning)" }}>
                              <div className="flex items-start gap-2">
                                <span className="mt-0.5 inline-flex h-4 w-4 flex-shrink-0 items-center justify-center rounded-full bg-[var(--warning)]/15 text-[9px] font-bold text-[var(--warning)]">
                                  {i + 1}
                                </span>
                                <div className="min-w-0">
                                  <p className="text-[12px] font-semibold text-text truncate">{issue.scenarioName || issue.type}</p>
                                  <p className="mt-0.5 text-[11px] text-muted line-clamp-2 leading-relaxed">{issue.message}</p>
                                </div>
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                );
              })()}
            </article>

          </section>
        </main>
      </div>
    </>
  );
};

const EmptyState = ({ title, message }) => (
  <div className="flex h-full min-h-[350px] items-center justify-center p-8">
    <div className="text-center p-6 max-w-md flex flex-col items-center gap-2">
      <ShieldCheck className="w-12 h-12 text-success mx-auto mb-2" />
      <h2 className="text-lg font-semibold text-[var(--text)]">{title || "Scan Not Initiated"}</h2>
      <p className="text-sm text-[var(--muted)] leading-relaxed">{message || "Start a new scan to find issues."}</p>
    </div>
  </div>
);

const getSourceFileLabel = (file) => {
  if (!file || file === "N/A") return null;
  const normalized = String(file).replace(/\\/g, "/");
  const parts = normalized.split("/").filter(Boolean);
  return parts[parts.length - 1] || normalized;
};

const buildSpecSourceContext = ({ file, line, method, endpoint, message, category }) => {
  const fileLabel = getSourceFileLabel(file) || "source";
  const lineLabel = line ? String(line) : "?";
  const httpMethod = String(method || "GET").toUpperCase();
  const path = endpoint || "/resource";
  const note = String(message || category || "Security finding").trim();
  const isJava = /\.java$/i.test(String(file || ""));
  const isJs = /\.(js|jsx|ts|tsx)$/i.test(String(file || ""));
  const mapping =
    {
      GET: "GetMapping",
      POST: "PostMapping",
      PUT: "PutMapping",
      DELETE: "DeleteMapping",
      PATCH: "PatchMapping",
    }[httpMethod] || "RequestMapping";

  if (isJava) {
    return [
      `// ${fileLabel}:${lineLabel}`,
      `@${mapping}("${path}")`,
      "public ResponseEntity<?> handler(@PathVariable Long id) {",
      `    // ${note}`,
      "    return ResponseEntity.ok(service.findById(id));",
      "}",
    ].join("\n");
  }

  if (isJs) {
    return [
      `// ${fileLabel}:${lineLabel}`,
      `router.${httpMethod.toLowerCase()}("${path}", async (req, res) => {`,
      `  // ${note}`,
      "  const item = await service.findById(req.params.id);",
      "  return res.json(item);",
      "});",
    ].join("\n");
  }

  return [
    `# ${fileLabel}:${lineLabel}`,
    `@app.route("${path}", methods=["${httpMethod}"])`,
    "def handler(id):",
    `    # ${note}`,
    "    return service.find_by_id(id)",
  ].join("\n");
};

const getSpecRemediationExamples = ({ rule, category, method, endpoint, file }) => {
  const r = String(rule || "").toUpperCase();
  const cat = String(category || "").toUpperCase();
  const httpMethod = String(method || "GET").toUpperCase();
  const path = endpoint || "/resource/{id}";
  const isJava = /\.java$/i.test(String(file || ""));
  const mapping =
    {
      GET: "GetMapping",
      POST: "PostMapping",
      PUT: "PutMapping",
      DELETE: "DeleteMapping",
      PATCH: "PatchMapping",
    }[httpMethod] || "RequestMapping";

  const apiNum = (r.match(/API[-_ ]?(\d+)/) || [])[1] || null;
  const isBola = cat === "BOLA" || apiNum === "1";
  const isAuth = cat === "AUTHENTICATION" || apiNum === "2";

  if (isBola && isJava) {
    return {
      bad: [
        `@${mapping}("${path}")`,
        "public Resource getById(@PathVariable Long id) {",
        "    // Returns the object without verifying the caller owns it",
        "    return service.findById(id);",
        "}",
      ].join("\n"),
    };
  }

  if (isBola) {
    return {
      bad: [
        `@app.route("${path}", methods=["${httpMethod}"])`,
        "def get_by_id(id):",
        "    # Returns the object without verifying the caller owns it",
        "    return service.find_by_id(id)",
      ].join("\n"),
    };
  }

  if (isAuth && isJava) {
    return {
      bad: [
        `@${mapping}("${path}")`,
        "// No authentication / authorization annotation",
        "public ResponseEntity<?> handle(...) {",
        "    return ResponseEntity.ok(service.execute(...));",
        "}",
      ].join("\n"),
    };
  }

  if (isAuth) {
    return {
      bad: [
        `@app.route("${path}", methods=["${httpMethod}"])`,
        "def handle():",
        "    # Endpoint is publicly reachable",
        "    return service.execute()",
      ].join("\n"),
    };
  }

  return null;
};

const getCategoryFromRule = (rule, message = "") => {
  const msg = String(message || "").toLowerCase();
  // Prefer message content when it clearly indicates auth vs BOLA
  // (handles legacy API1 rows that still say "does not enforce authentication").
  if (msg.includes("potential bola") || (msg.includes("bola") && !msg.includes("authentication"))) {
    return "BOLA";
  }
  if (
    msg.includes("does not enforce authentication") ||
    msg.includes("authentication missing") ||
    msg.includes("no security schemes") ||
    msg.includes("insecure authentication")
  ) {
    return "Authentication";
  }

  const r = String(rule || "").toUpperCase();
  // Checkov first, since "OPENAPI" contains "API" and would match the OWASP regex below.
  if (r.startsWith("CKV")) {
    const ckv = r.match(/CKV[_-]OPENAPI[_-](\d+)/);
    const n = ckv ? ckv[1] : "";
    if (["3", "18", "20"].includes(n)) return "Transport Security";
    if (["8", "12", "15"].includes(n)) return "Weak Auth";
    if (["1", "4", "5"].includes(n)) return "Security Definition";
    if (n === "21") return "Resource Limits";
    return "Checkov";
  }
  // OWASP API Top 10 — match the exact API number (so API10 != API1).
  const apiMatch = r.match(/API[-_ ]?(\d+)/);
  if (apiMatch) {
    const owaspCategories = {
      "1": "BOLA",
      "2": "Authentication",
      "3": "BOPLA",
      "4": "Rate Limiting",
      "5": "BFLA",
      "6": "Business Flows",
      "7": "SSRF",
      "8": "Misconfiguration",
      "9": "Inventory",
      "10": "Unsafe Consumption",
    };
    return owaspCategories[apiMatch[1]] || "API Security";
  }
  if (r.includes("SCHEMA-001")) return "Schema Validation";
  if (r.includes("SCHEMA-002")) return "Response Schema";
  if (r.includes("SCHEMA-003")) return "Input Validation";
  if (r.includes("SCHEMA-004")) return "Content Type";
  if (r.includes("MISSING_REQUEST_BODY")) return "Payload Schema";
  return "General";
};

const getProtocolFromRow = (row) => {
  if (row.protocol) return String(row.protocol).toUpperCase();
  const ep = String(row.endpoint || "").toLowerCase();
  if (ep.includes("graphql") || ep.includes("/gql")) return "GraphQL";
  if (ep.includes("grpc") || ep.includes(".proto")) return "gRPC";
  if (ep.includes("soap") || ep.includes("wsdl")) return "SOAP";
  return "REST";
};

const formatPath = (path) => {
  const trimmed = String(path || "").trim();
  return trimmed || "N/A";
};

const formatEndpoint = (method, path) => {
  const hasMethod = Boolean(method && String(method).trim());
  const hasPath = Boolean(path && String(path).trim());

  if (!hasMethod && !hasPath) return "N/A";
  if (!hasMethod) return String(path);
  if (!hasPath) return String(method).toUpperCase();

  return `${String(method).toUpperCase()} ${String(path)}`;
};

const clamp = (value, min, max) => Math.min(max, Math.max(min, value));

const formatDate = (rawDate) => {
  if (!rawDate) return "N/A";
  const parsed = new Date(rawDate);
  return Number.isNaN(parsed.getTime()) ? "N/A" : parsed.toLocaleDateString();
};

const formatDateTime = (rawDate) => {
  if (!rawDate) return "N/A";
  const parsed = new Date(rawDate);
  if (Number.isNaN(parsed.getTime())) return "N/A";

  return parsed.toLocaleString([], {
    year: "numeric",
    month: "long",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
};

const normalizeStatus = (value) => String(value || "").trim().toLowerCase();

const getSeverityColor = (severity) => {
  const colors = {
    critical: "#FB7185",
    high: "#FB923C",
    medium: "#FBBF24",
    low: "#22D3EE",
  };
  return colors[severity] || "#94A3B8";
};

const getScoreColor = (score) => {
  if (score >= 90) return "#22C55E";
  if (score >= 70) return "#F59E0B";
  return "#EF4444";
};

const getSeverityBadgeStyle = (severity) => {
  return getSharedSeverityBadgeStyle(severity);
};

const renderSeverityBadge = (severity) => {
  const tone = normalizeSeverity(severity);
  const cfg = SEVERITY_FIGMA_COLORS[tone] || {
    text: "var(--text-secondary)",
    bg: "var(--elevated)",
    border: "var(--border)",
  };

  return (
    <span
      className="inline-flex items-center justify-center rounded-[5px] px-2.5 py-1 text-xs font-normal capitalize"
      style={{
        backgroundColor: cfg.bg,
        color: cfg.text,
      }}
    >
      {formatApiText(severity)}
    </span>
  );
};

export default SpecScanner;
