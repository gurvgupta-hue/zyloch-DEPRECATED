import React from "react";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

jest.mock("next/dynamic", () => () => {
  const Stub = () => <div data-testid="chart-stub" />;
  Stub.displayName = "DynamicStub";
  return Stub;
});

jest.mock("tech-stack-icons", () => {
  const MockIcon = () => <span data-testid="stack-icon" />;
  return {
    __esModule: true,
    default: MockIcon,
  };
});

jest.mock("@/app/scanops/components/scan/shared/textUtils", () => ({
  formatApiText: (v) => String(v),
}));

jest.mock("@/app/scanops/components/scan/shared/severityVisuals", () => ({
  formatSeverityLabel: (v) => String(v).toUpperCase(),
  getSeverityBadgeStyle: () => ({}),
  getSeverityIcon: () => () => <span data-testid="severity-icon" />,
  normalizeSeverity: (v) => String(v || "").toLowerCase(),
  SEVERITY_FIGMA_COLORS: {
    critical: { text: "#EF4444", bg: "rgba(239, 68, 68, 0.15)", border: "rgba(239, 68, 68, 0.3)", dot: "#EF4444" },
    high: { text: "#F97316", bg: "rgba(249, 115, 22, 0.15)", border: "rgba(249, 115, 22, 0.3)", dot: "#F97316" },
    medium: { text: "#3B82F6", bg: "rgba(59, 130, 246, 0.15)", border: "rgba(59, 130, 246, 0.3)", dot: "#3B82F6" },
    low: { text: "#8B5CF6", bg: "rgba(139, 92, 246, 0.15)", border: "rgba(139, 92, 246, 0.3)", dot: "#8B5CF6" },
  },
  getFigmaSeverityBadgeStyle: () => ({}),
  getSeverityColorToken: () => "#000",
  TableSeverityBadge: ({ severity }) => <span data-testid="table-severity-badge">{severity}</span>,
}));

jest.mock("@/app/scanops/components/scan/iac/PolicyDetailsSidebar", () => {
  return function PolicyDetailsSidebar({ isOpen, onClose, finding }) {
    if (!isOpen) return null;
    return (
      <div data-testid="policy-sidebar">
        <span>{finding?.policyCode}</span>
        <span data-testid="sidebar-file">{finding?.file}</span>
        <span data-testid="sidebar-line">{finding?.lineNo}</span>
        <span data-testid="sidebar-endpoint">{finding?.endpoint}</span>
        <pre data-testid="sidebar-code-block">{finding?.codeBlock || ""}</pre>
        <pre data-testid="sidebar-example-bad">{finding?.examples?.bad || ""}</pre>
        <pre data-testid="sidebar-example-good">{finding?.examples?.good || ""}</pre>
        <button onClick={onClose}>Close</button>
      </div>
    );
  };
});

const mockStoreState = {
  latestScan: null,
  loading: false,
  error: null,
};

jest.mock("@/store/useScanStore", () => ({
  useScanStore: () => mockStoreState,
}));

import SpecScanner from "@/app/scanops/components/scan/spec-scanner/SpecScanner";

function setStore(patch) {
  Object.assign(mockStoreState, {
    latestScan: null,
    loading: false,
    error: null,
    ...patch,
  });
}

function buildScan({
  apiViolations = [],
  payloadViolations = [],
  checks = [],
  apis = [],
  score = 75,
} = {}) {
  return {
    scan_id: "scan-1",
    scan_status: "completed",
    created_at: "2026-05-17T10:00:00Z",
    scan_metadata: {
      organization: "test-org",
      repository: "test-repo",
      branch: "main",
      commit_author: "dev.user",
      scan_timestamp: "2026-05-17T10:00:00Z",
    },
    scan_results: {
      scan_results: {
        summary: {
          score_summary: {
            score_by_subscan: { "spec-scanner": score },
          },
          issues_summary: {
            issue_counts_by_subscan_and_severity: {
              "spec-scanner": {
                critical: 1,
                high: 1,
                medium: 1,
                low: 0,
              },
            },
          },
        },
        scanner_results: {},
      },
      generator_validator: {
        scan: {
          meta: {
            totalViolations: apiViolations.length + payloadViolations.length,
            totalApis: apis.length,
            vulnerableApis: apis.filter((a) => !a.secure).length,
            passed: checks.filter((c) => c.status === "passed").length,
            failed: checks.filter((c) => c.status === "failed").length,
          },
          checks,
          apis,
          apiViolations,
          payloadViolations,
        },
      },
      scans_findings: {},
      scans_status: {},
    },
  };
}

const VIOLATIONS = [
  {
    violationId: "OWASP-API1",
    severity: "critical",
    method: "GET",
    path: "/api/users/{id}",
    message: "No object-level authorization check found.",
    file: "app/routes/users.py",
    line: 42,
    code_block: "@GetMapping(\"/api/users/{id}\")\npublic User getUser(@PathVariable Long id) {\n  return userService.findById(id);\n}",
  },
  {
    violationId: "OWASP-API2",
    severity: "high",
    method: "POST",
    path: "/api/payments",
    message: "Payment endpoint has no authentication.",
    file: "app/routes/payments.py",
    line: 18,
  },
  {
    violationId: "OWASP-API4",
    severity: "medium",
    method: "GET",
    path: "/api/products",
    message: "No rate limiting defined.",
    file: "app/routes/products.py",
    line: 55,
  },
];

const PAYLOAD_VIOLATIONS = [
  {
    rule: "SCHEMA-001",
    severity: "medium",
    method: "POST",
    path: "/api/users",
    message: "Email field missing strict validation.",
    location: "requestBody",
    file: "app/routes/users.py",
    line: 20,
  },
];

const CHECKS = [
  {
    id: "OWASP-API1",
    name: "Broken Object Level Authorization",
    status: "failed",
    severity: "critical",
  },
  {
    id: "OWASP-API2",
    name: "Broken Authentication",
    status: "passed",
    severity: "high",
  },
];

describe("SpecScanner", () => {
  beforeEach(() => {
    setStore({});
  });

  it("renders loading state", () => {
    setStore({ loading: true });
    render(<SpecScanner />);
    expect(screen.getByText(/loading api discovery data/i)).toBeInTheDocument();
  });

  it("renders empty state when no scan exists", () => {
    setStore({ latestScan: null });
    render(<SpecScanner />);
    expect(screen.getByText(/scan not initiated/i)).toBeInTheDocument();
  });

  it("renders main title and metadata for a valid scan", () => {
    setStore({ latestScan: buildScan({ apiViolations: VIOLATIONS, checks: CHECKS }) });
    render(<SpecScanner />);

    expect(screen.getByText(/api discovery security analysis/i)).toBeInTheDocument();
    expect(screen.getByText("test-org/test-repo")).toBeInTheDocument();
    expect(screen.getByText("dev.user")).toBeInTheDocument();
    expect(screen.getByText("main")).toBeInTheDocument();
  });

  it("renders findings from apiViolations and payloadViolations", () => {
    setStore({
      latestScan: buildScan({
        apiViolations: VIOLATIONS,
        payloadViolations: PAYLOAD_VIOLATIONS,
      }),
    });
    render(<SpecScanner />);

    expect(screen.getByText("OWASP-API1")).toBeInTheDocument();
    expect(screen.getByText("OWASP-API2")).toBeInTheDocument();
    expect(screen.getByText("SCHEMA-001")).toBeInTheDocument();
    // Endpoint column shows path only (method has its own column).
    expect(screen.getByText("/api/users/{id}")).toBeInTheDocument();
    expect(screen.getByText("BOLA")).toBeInTheDocument();
    expect(screen.getByText("Authentication")).toBeInTheDocument();
  });

  it("filters findings via search box", async () => {
    const user = userEvent.setup();
    setStore({ latestScan: buildScan({ apiViolations: VIOLATIONS }) });
    render(<SpecScanner />);

    await user.type(screen.getByPlaceholderText(/search rule, endpoint, or message/i), "payments");

    expect(screen.getByText("OWASP-API2")).toBeInTheDocument();
    expect(screen.queryByText("OWASP-API1")).not.toBeInTheDocument();
  });

  it("renders API Inventory view with file, line, and secure status", async () => {
    const user = userEvent.setup();
    setStore({
      latestScan: buildScan({
        apiViolations: VIOLATIONS,
        apis: [
          {
            method: "GET",
            path: "/api/inventory/{skuCode}",
            file: "inventory-service/src/main/java/com/vit/inventory_service/controller/InventoryController.java",
            line: 21,
            secure: false,
            payloadViolationCount: 0,
          },
        ],
      }),
    });
    render(<SpecScanner />);

    await user.selectOptions(screen.getByRole("combobox", { name: /select report view/i }), "api-inventory");
    expect(screen.getByRole("heading", { name: /api inventory/i })).toBeInTheDocument();
    expect(screen.getByText("/api/inventory/{skuCode}")).toBeInTheDocument();
    expect(screen.getByText(/InventoryController\.java/)).toBeInTheDocument();
    expect(screen.getByText("21")).toBeInTheDocument();
    expect(screen.getByText("Vulnerable")).toBeInTheDocument();
  });

  it("opens sidebar when clicking view details action", async () => {
    const user = userEvent.setup();
    setStore({ latestScan: buildScan({ apiViolations: VIOLATIONS }) });
    render(<SpecScanner />);

    await user.click(screen.getAllByRole("button", { name: /view details/i })[0]);
    expect(screen.getByTestId("policy-sidebar")).toBeInTheDocument();
    expect(screen.getByTestId("sidebar-file")).toHaveTextContent("app/routes/users.py");
    expect(screen.getByTestId("sidebar-line")).toHaveTextContent("42");
    expect(screen.getByTestId("sidebar-endpoint")).toHaveTextContent("/api/users/{id}");
    expect(screen.getByTestId("sidebar-code-block")).toHaveTextContent(
      "return userService.findById(id);"
    );
    expect(screen.getByTestId("sidebar-example-bad")).toHaveTextContent(
      "without verifying the caller owns it"
    );
    expect(screen.getByTestId("sidebar-example-good")).toHaveTextContent("");
  });

  it("reconstructs source context when apiViolation has no code_block", async () => {
    const user = userEvent.setup();
    setStore({
      latestScan: buildScan({
        apiViolations: [
          {
            violationId: "OWASP-API1",
            severity: "critical",
            method: "GET",
            path: "/api/user/{id}",
            message: "Potential BOLA: GET /api/user/{id} lacks authorization checks.",
            file: "src/main/java/com/example/UserController.java",
            line: 35,
          },
        ],
      }),
    });
    render(<SpecScanner />);

    await user.click(screen.getAllByRole("button", { name: /view details/i })[0]);
    expect(screen.getByTestId("sidebar-code-block")).toHaveTextContent("@GetMapping");
    expect(screen.getByTestId("sidebar-code-block")).toHaveTextContent("UserController.java:35");
    expect(screen.getByTestId("sidebar-code-block")).toHaveTextContent("Potential BOLA");
  });

  it("maps fallback Spec-Scanner-findings file_name as endpoint and file as source path", async () => {
    const user = userEvent.setup();
    const scan = buildScan({ apiViolations: [], payloadViolations: [], checks: [] });
    scan.scan_results.scans_findings = {
      "Spec-Scanner-findings": [
        {
          file_name: "POST /api/order",
          file: "app/routes/order.py",
          violated_policies: [
            {
              policy_name: "OWASP-API2-AUTH",
              description: "Authentication missing on POST /api/order",
              severity: "critical",
              Line_No: "88",
              Matches: "Authentication missing on POST /api/order",
            },
          ],
        },
      ],
    };
    setStore({ latestScan: scan });
    render(<SpecScanner />);
    expect(screen.getByText("OWASP-API2-AUTH")).toBeInTheDocument();
    expect(screen.getByText("/api/order")).toBeInTheDocument();

    await user.click(screen.getAllByRole("button", { name: /view details/i })[0]);
    expect(screen.getByTestId("sidebar-file")).toHaveTextContent("app/routes/order.py");
    expect(screen.getByTestId("sidebar-line")).toHaveTextContent("88");
    expect(screen.getByTestId("sidebar-endpoint")).toHaveTextContent("/api/order");
  });

  it("paginates when findings exceed page size", async () => {
    const user = userEvent.setup();
    const manyViolations = Array.from({ length: 30 }, (_, i) => ({
      violationId: `RULE-${String(i + 1).padStart(3, "0")}`,
      severity: "low",
      method: "GET",
      path: `/api/ep-${i}`,
      message: `Message ${i}`,
    }));

    setStore({ latestScan: buildScan({ apiViolations: manyViolations }) });
    render(<SpecScanner />);

    expect(screen.queryByText("RULE-030")).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /next page/i }));
    expect(screen.getByText("RULE-030")).toBeInTheDocument();
  });
});
