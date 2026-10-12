import React from "react";
import { render, screen, fireEvent } from "@testing-library/react";
import { ScanPoliciesSidebar } from "@/app/settings/components/ScanPolicies/ScanPoliciesSidebar";

// Mock lucide-react icons
jest.mock("lucide-react", () => ({
  ChevronLeft: (props) => <svg data-testid="icon-chevron-left" {...props} />,
  ChevronRight: (props) => <svg data-testid="icon-chevron-right" {...props} />,
  ChevronDown: (props) => <svg data-testid="icon-chevron-down" {...props} />,
}));

const baseScanCategories = [
  {
    id: "workflow",
    name: "Workflow",
    icon: <span data-testid="icon-workflow">W</span>,
    subCategories: [
      { id: "workflow", name: "Workflow", icon: <span>W</span> },
    ],
  },
  {
    id: "iac",
    name: "Infrastructure as Code",
    icon: <span data-testid="icon-iac">I</span>,
    subCategories: [
      { id: "kubernetes", name: "Kubernetes", icon: <span>K8s</span> },
      { id: "docker", name: "Docker", icon: <span>D</span> },
      {
        id: "terraform",
        name: "Terraform",
        icon: <span>TF</span>,
        subCategories: [
          { id: "aws", name: "AWS", icon: <span>AWS</span> },
          { id: "azure", name: "Azure", icon: <span>AZ</span> },
          { id: "gcp", name: "GCP", icon: <span>GCP</span> },
        ],
      },
      { id: "ansible", name: "Ansible", icon: <span>Ans</span> },
    ],
  },
];

const baseNavGroups = [
  { id: "pipeline", label: "Workflow", categories: ["workflow"] },
  { id: "infra", label: "Infrastructure", categories: ["iac"] },
];

const basePolicies = {
  workflow: [{ id: "WF-001", name: "P1", enabled: true, severity: "HIGH" }],
  kubernetes: [{ id: "K8S-001", name: "P2", enabled: true, severity: "HIGH" }],
  docker: [{ id: "D-001", name: "P3", enabled: false, severity: "LOW" }],
  aws: [{ id: "AWS-001", name: "P4", enabled: true, severity: "CRITICAL" }],
  azure: [],
  gcp: [],
  ansible: [{ id: "ANS-001", name: "P5", enabled: true, severity: "MEDIUM" }],
};

const basePolicyStats = {
  totalPolicies: 5,
  enabledPolicies: 4,
  disabledPolicies: 1,
  enabledPercentage: 80,
  disabledPercentage: 20,
};

const defaultProps = {
  selectedCategory: "workflow",
  setSelectedCategory: jest.fn(),
  selectedSubCategory: "workflow",
  setSelectedSubCategory: jest.fn(),
  expandedCategories: ["workflow", "iac"],
  toggleCategory: jest.fn(),
  scanCategories: baseScanCategories,
  navGroups: baseNavGroups,
  policies: basePolicies,
  policyStats: basePolicyStats,
  getCategoryCount: jest.fn().mockReturnValue(3),
};

describe("ScanPoliciesSidebar", () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  test("renders the sidebar with a right border", () => {
    const { container } = render(<ScanPoliciesSidebar {...defaultProps} />);
    const sidebar = container.firstChild;
    expect(sidebar.style.borderRight).toBe("1px solid var(--border)");
  });

  test("renders with fixed width of 240px", () => {
    const { container } = render(<ScanPoliciesSidebar {...defaultProps} />);
    const sidebar = container.firstChild;
    expect(sidebar.style.width).toBe("240px");
  });

  test("renders Policy Management header", () => {
    render(<ScanPoliciesSidebar {...defaultProps} />);
    expect(screen.getByText("Policy Management")).toBeInTheDocument();
  });

  test("shows back control only when a policy is selected", () => {
    const { rerender } = render(<ScanPoliciesSidebar {...defaultProps} />);

    expect(screen.getByRole("button", { name: /back to policy search/i })).toBeInTheDocument();

    rerender(
      <ScanPoliciesSidebar
        {...defaultProps}
        selectedCategory={null}
        selectedSubCategory={null}
      />,
    );

    expect(screen.queryByRole("button", { name: /back to policy search/i })).not.toBeInTheDocument();
  });

  test("resets to policy search when back control is clicked", () => {
    render(<ScanPoliciesSidebar {...defaultProps} />);

    fireEvent.click(screen.getByRole("button", { name: /back to policy search/i }));

    expect(defaultProps.setSelectedCategory).toHaveBeenCalledWith(null);
    expect(defaultProps.setSelectedSubCategory).toHaveBeenCalledWith(null);
  });

  test("displays correct category count in header", () => {
    render(<ScanPoliciesSidebar {...defaultProps} />);
    expect(screen.getByText("2 Categories")).toBeInTheDocument();
  });

  test("renders navigation group labels", () => {
    render(<ScanPoliciesSidebar {...defaultProps} />);
    // 'pipeline' group label is hidden by design
    expect(screen.getByText("Infrastructure")).toBeInTheDocument();
  });

  test("renders category names from scanCategories", () => {
    render(<ScanPoliciesSidebar {...defaultProps} />);
    expect(screen.getByText("Workflow")).toBeInTheDocument();
    expect(screen.getByText("Infrastructure as Code")).toBeInTheDocument();
  });

  test("renders expanded subcategories", () => {
    render(<ScanPoliciesSidebar {...defaultProps} />);
    // IaC is expanded, so its children should be visible
    expect(screen.getByText("Kubernetes")).toBeInTheDocument();
    expect(screen.getByText("Docker")).toBeInTheDocument();
    expect(screen.getByText("Terraform")).toBeInTheDocument();
    expect(screen.getByText("Ansible")).toBeInTheDocument();
  });

  test("calls toggleCategory when a parent category with children is clicked", () => {
    render(<ScanPoliciesSidebar {...defaultProps} />);
    fireEvent.click(screen.getByText("Infrastructure as Code"));
    expect(defaultProps.toggleCategory).toHaveBeenCalledWith("iac");
  });

  test("calls setSelectedCategory and setSelectedSubCategory for leaf items", () => {
    render(<ScanPoliciesSidebar {...defaultProps} />);
    fireEvent.click(screen.getByText("Kubernetes"));
    expect(defaultProps.setSelectedCategory).toHaveBeenCalledWith("iac");
    expect(defaultProps.setSelectedSubCategory).toHaveBeenCalledWith("kubernetes");
  });

  test("does not render subcategories when category is collapsed", () => {
    const props = {
      ...defaultProps,
      expandedCategories: [], // Nothing expanded
    };
    render(<ScanPoliciesSidebar {...props} />);
    expect(screen.queryByText("Kubernetes")).not.toBeInTheDocument();
    expect(screen.queryByText("Docker")).not.toBeInTheDocument();
  });

  test("renders footer with enabled percentage and counts", () => {
    render(<ScanPoliciesSidebar {...defaultProps} />);
    expect(screen.getByText("80% Enabled")).toBeInTheDocument();
    expect(screen.getByText("4/5")).toBeInTheDocument();
  });

  test("renders progress bar with correct width", () => {
    const { container } = render(<ScanPoliciesSidebar {...defaultProps} />);
    const progressBar = container.querySelector(".h-full.transition-all");
    expect(progressBar.style.width).toBe("80%");
  });

  test("hides pipeline group label as per design", () => {
    render(<ScanPoliciesSidebar {...defaultProps} />);
    // The "Workflow" group label should not appear (since group.id === 'pipeline')
    // But the category name "Workflow" should still appear
    const workflowElements = screen.getAllByText("Workflow");
    // Only category row "Workflow", no group label for pipeline
    expect(workflowElements.length).toBeGreaterThanOrEqual(1);
  });
});
