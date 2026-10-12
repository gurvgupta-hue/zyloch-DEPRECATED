import React from "react";
import { render, screen, fireEvent } from "@testing-library/react";
import ScanPoliciesList from "@/app/settings/components/ScanPolicies/ScanPoliciesList";
import { toast } from "react-toastify";

// Mock react-toastify
jest.mock("react-toastify", () => ({
  toast: Object.assign(jest.fn(), {
    dismiss: jest.fn(),
  }),
}));

// Mock PolicyRow to keep tests focused
jest.mock("@/components/policy/PolicyRow", () => {
  return function MockPolicyRow({ title, severity, enabled, onToggle }) {
    return (
      <div data-testid={`policy-row-${title}`}>
        <span>{title}</span>
        <span data-testid={`severity-${title}`}>{severity}</span>
        <button data-testid={`toggle-${title}`} onClick={onToggle}>
          {enabled ? "Enabled" : "Disabled"}
        </button>
      </div>
    );
  };
});

const baseScanCategories = [
  {
    id: "workflow",
    name: "Workflow",
    subCategories: [{ id: "workflow", name: "Workflow" }],
  },
  {
    id: "iac",
    name: "Infrastructure as Code",
    subCategories: [
      { id: "kubernetes", name: "Kubernetes" },
      { id: "docker", name: "Docker" },
      {
        id: "terraform",
        name: "Terraform",
        subCategories: [
          { id: "aws", name: "AWS" },
          { id: "azure", name: "Azure" },
          { id: "gcp", name: "GCP" },
        ],
      },
      { id: "ansible", name: "Ansible" },
    ],
  },
];

const basePolicies = {
  workflow: [
    { id: "WF-001", name: "Checkout Security", enabled: true, severity: "HIGH", description: "Check checkout actions" },
    { id: "WF-002", name: "Artifact Verification", enabled: false, severity: "CRITICAL", description: "Verify artifacts" },
  ],
  kubernetes: [
    { id: "K8S-001", name: "Privileged Containers", enabled: true, severity: "HIGH", description: "No privileged" },
  ],
  docker: [
    { id: "D-001", name: "Latest Tag", enabled: true, severity: "LOW", description: "Avoid latest tag" },
  ],
  aws: [
    { id: "AWS-001", name: "AWS RDS Encryption", enabled: true, severity: "CRITICAL", description: "Encrypt RDS" },
  ],
  azure: [
    { id: "AZ-001", name: "Azure Storage HTTPS", enabled: true, severity: "HIGH", description: "Use HTTPS" },
  ],
  gcp: [
    { id: "GCP-001", name: "GCP Bucket Access", enabled: true, severity: "MEDIUM", description: "Restrict access" },
  ],
  ansible: [
    { id: "ANS-001", name: "Ansible Hardcoded Secrets", enabled: true, severity: "HIGH", description: "No hardcoded secrets" },
  ],
};

const defaultProps = {
  selectedCategory: "workflow",
  selectedSubCategory: "workflow",
  scanCategories: baseScanCategories,
  policies: basePolicies,
  onPolicyToggle: jest.fn(),
  onSeverityChange: jest.fn(),
  getSeverityColor: jest.fn().mockReturnValue(""),
  getSeverityIcon: jest.fn().mockReturnValue(null),
  activeTab: "policies",
  onTabChange: jest.fn(),
  onBulkToggle: jest.fn(),
  onMobileMenuOpen: jest.fn(),
  onCategoryChange: jest.fn(),
  unsavedChangesCount: 0,
  onSavePreferences: jest.fn(),
  onDiscardChanges: jest.fn(),
};

describe("ScanPoliciesList", () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  // ── Rendering tests ──────────────────────────────────────────

  test("renders policy list with workflow policies", () => {
    render(<ScanPoliciesList {...defaultProps} />);
    expect(screen.getByText("Checkout Security")).toBeInTheDocument();
    expect(screen.getByText("Artifact Verification")).toBeInTheDocument();
  });

  test("renders breadcrumb with category name", () => {
    render(<ScanPoliciesList {...defaultProps} />);
    expect(screen.getByText("Security")).toBeInTheDocument();
    // "Workflow" appears in breadcrumb, sub-breadcrumb, and title
    const workflowElements = screen.getAllByText("Workflow");
    expect(workflowElements.length).toBeGreaterThanOrEqual(1);
  });

  test("renders search bar", () => {
    render(<ScanPoliciesList {...defaultProps} />);
    expect(screen.getByPlaceholderText(/Search Workflow policies.../i)).toBeInTheDocument();
  });

  test("renders severity filter dropdown", () => {
    render(<ScanPoliciesList {...defaultProps} />);
    const severitySelect = screen.getByDisplayValue("Severity: All");
    expect(severitySelect).toBeInTheDocument();
  });

  test("renders status filter dropdown", () => {
    render(<ScanPoliciesList {...defaultProps} />);
    const statusSelect = screen.getByDisplayValue("Status: All");
    expect(statusSelect).toBeInTheDocument();
  });

  // ── Cloud tabs tests (light mode fix) ───────────────────────

  test("renders cloud provider tabs for terraform view", () => {
    const props = {
      ...defaultProps,
      selectedCategory: "iac",
      selectedSubCategory: "terraform",
    };
    render(<ScanPoliciesList {...props} />);
    expect(screen.getByText("All")).toBeInTheDocument();
    expect(screen.getByText("AWS")).toBeInTheDocument();
    expect(screen.getByText("AZURE")).toBeInTheDocument();
    expect(screen.getByText("GCP")).toBeInTheDocument();
  });

  test("cloud provider tabs use CSS variables instead of hardcoded dark-mode colors", () => {
    const props = {
      ...defaultProps,
      selectedCategory: "iac",
      selectedSubCategory: "terraform",
    };
    const { container } = render(<ScanPoliciesList {...props} />);

    // Find inactive cloud tab buttons (non-active ones)
    const tabButtons = container.querySelectorAll("button");
    const cloudTabs = Array.from(tabButtons).filter((btn) => {
      const text = btn.textContent;
      return ["AWS", "AZURE", "GCP"].includes(text.trim().replace(/\d+/g, "").trim());
    });

    cloudTabs.forEach((tab) => {
      // Should NOT have hardcoded dark-mode colors
      expect(tab.style.background).not.toBe("#1E1E1E");
      expect(tab.style.color).not.toBe("#FFFFFF");
      expect(tab.style.border).not.toContain("#323232");
    });
  });

  test("active cloud tab has correct styling", () => {
    const props = {
      ...defaultProps,
      selectedCategory: "iac",
      selectedSubCategory: "terraform",
    };
    const { container } = render(<ScanPoliciesList {...props} />);

    // The "All" tab is active by default
    const tabButtons = container.querySelectorAll("button");
    const allTab = Array.from(tabButtons).find((btn) => btn.textContent.trim().startsWith("All"));
    if (allTab) {
      expect(allTab.style.background).toBe("rgba(var(--color-primary-rgb),0.15)");
      expect(allTab.style.color).toBe("var(--color-primary)");
    }
  });

  test("does not render cloud tabs for non-terraform categories", () => {
    render(<ScanPoliciesList {...defaultProps} />);
    // For workflow view, no cloud tabs should appear
    const allTabs = screen.queryAllByText("AWS");
    // The AWS button should not be present (only policy rows)
    const cloudTabButtons = allTabs.filter((el) => el.tagName === "BUTTON" || el.closest("button"));
    expect(cloudTabButtons).toHaveLength(0);
  });

  // ── Search / filter tests ───────────────────────────────────

  test("filters policies by search term", () => {
    render(<ScanPoliciesList {...defaultProps} />);
    const searchInput = screen.getByPlaceholderText(/Search Workflow policies.../i);
    fireEvent.change(searchInput, { target: { value: "Checkout" } });
    expect(screen.getByText("Checkout Security")).toBeInTheDocument();
    expect(screen.queryByText("Artifact Verification")).not.toBeInTheDocument();
  });

  test("filters policies by severity", () => {
    render(<ScanPoliciesList {...defaultProps} />);
    const severitySelect = screen.getByDisplayValue("Severity: All");
    fireEvent.change(severitySelect, { target: { value: "HIGH" } });
    expect(screen.getByText("Checkout Security")).toBeInTheDocument();
    expect(screen.queryByText("Artifact Verification")).not.toBeInTheDocument();
  });

  test("filters policies by enabled status", () => {
    render(<ScanPoliciesList {...defaultProps} />);
    const statusSelect = screen.getByDisplayValue("Status: All");
    fireEvent.change(statusSelect, { target: { value: "DISABLED" } });
    expect(screen.queryByText("Checkout Security")).not.toBeInTheDocument();
    expect(screen.getByText("Artifact Verification")).toBeInTheDocument();
  });

  // ── Toggle/action tests ─────────────────────────────────────

  test("calls onPolicyToggle when a policy toggle is clicked", () => {
    render(<ScanPoliciesList {...defaultProps} />);
    const toggleBtn = screen.getByTestId("toggle-Checkout Security");
    fireEvent.click(toggleBtn);
    expect(defaultProps.onPolicyToggle).toHaveBeenCalledWith("WF-001", "workflow");
  });

  // ── Empty state test ────────────────────────────────────────

  test("shows empty state when no policies match filters", () => {
    render(<ScanPoliciesList {...defaultProps} />);
    const searchInput = screen.getByPlaceholderText(/Search Workflow policies.../i);
    fireEvent.change(searchInput, { target: { value: "nonexistent-xyz" } });
    expect(screen.getByText("No policies found")).toBeInTheDocument();
  });

  // ── Unsaved changes banner ──────────────────────────────────

  test("shows unsaved changes banner when count > 0", () => {
    const props = { ...defaultProps, unsavedChangesCount: 3 };
    render(<ScanPoliciesList {...props} />);
    expect(screen.getByText("3 unsaved changes")).toBeInTheDocument();
    expect(screen.getByText("Save preferences")).toBeInTheDocument();
    expect(screen.getByText("Discard")).toBeInTheDocument();
  });

  test("shows no-unsaved message and hides action buttons when count is 0", () => {
    render(<ScanPoliciesList {...defaultProps} />);
    expect(screen.getByText("No unsaved changes.")).toBeInTheDocument();
    expect(screen.queryByText("Save preferences")).not.toBeInTheDocument();
    expect(screen.queryByText("Discard")).not.toBeInTheDocument();
  });

  test("calls onSavePreferences when Save button is clicked", () => {
    const props = { ...defaultProps, unsavedChangesCount: 1 };
    render(<ScanPoliciesList {...props} />);
    fireEvent.click(screen.getByText("Save preferences"));
    expect(defaultProps.onSavePreferences).toHaveBeenCalledTimes(1);
    expect(toast.dismiss).toHaveBeenCalledTimes(1);
  });

  test("calls onDiscardChanges when Discard button is clicked", () => {
    const props = { ...defaultProps, unsavedChangesCount: 1 };
    render(<ScanPoliciesList {...props} />);
    fireEvent.click(screen.getByText("Discard"));
    expect(defaultProps.onDiscardChanges).toHaveBeenCalledTimes(1);
    expect(toast.dismiss).toHaveBeenCalledTimes(1);
  });

  // ── Pagination tests ────────────────────────────────────────

  test("renders pagination controls", () => {
    render(<ScanPoliciesList {...defaultProps} />);
    // Use getAllByText since "›" also appears in breadcrumb separators
    const prevButtons = screen.getAllByText("‹");
    const nextButtons = screen.getAllByText("›");
    expect(prevButtons.length).toBeGreaterThanOrEqual(1);
    expect(nextButtons.length).toBeGreaterThanOrEqual(1);
  });

  // ── Global search (selectedSubCategory not set) ─────────────

  test("shows global search UI when selectedSubCategory is null", () => {
    const props = {
      ...defaultProps,
      selectedSubCategory: null,
    };
    render(<ScanPoliciesList {...props} />);
    expect(screen.getByText("Find a Security Policy")).toBeInTheDocument();
    expect(
      screen.getByPlaceholderText(/Search by policy ID or name/i)
    ).toBeInTheDocument();
  });

  // ── Ansible category rendering ─────────────────────────────

  test("renders ansible policies correctly", () => {
    const props = {
      ...defaultProps,
      selectedCategory: "iac",
      selectedSubCategory: "ansible",
    };
    render(<ScanPoliciesList {...props} />);
    expect(screen.getByText("Ansible Hardcoded Secrets")).toBeInTheDocument();
  });

  // ── Footer summary ─────────────────────────────────────────

  test("renders footer with policy summary text", () => {
    render(<ScanPoliciesList {...defaultProps} />);
    expect(screen.getByText(/enabled · .* disabled · .* shown/i)).toBeInTheDocument();
  });
});
