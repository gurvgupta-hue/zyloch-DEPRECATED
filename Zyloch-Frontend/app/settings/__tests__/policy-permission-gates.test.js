import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import "@testing-library/jest-dom";
import ScanPoliciesCard from "../components/ScanPoliciesCard";
import { ScanOptionsCard } from "../components/ScanOptionsCard";

const scanToggle = jest.fn();
const secretToggle = jest.fn();
const bulkToggle = jest.fn();
const severityChange = jest.fn();
const toastInfo = jest.fn();

jest.mock("react-toastify", () => ({
  toast: { info: (...args) => toastInfo(...args) },
}));

jest.mock("@/context/ThemeContext", () => ({
  useTheme: jest.fn(() => ({ theme: "light" })),
}));

jest.mock("../components/ScanPolicies/useScanPolicies", () => ({
  useScanPolicies: () => ({
    selectedCategory: "iac",
    setSelectedCategory: jest.fn(),
    selectedSubCategory: "docker",
    setSelectedSubCategory: jest.fn(),
    expandedCategories: {},
    toggleCategory: jest.fn(),
    policies: { docker: [] },
    handlePolicyToggle: scanToggle,
    handleSeverityChange: severityChange,
    handleBulkToggle: bulkToggle,
    getSeverityColor: () => "red",
    getSeverityIcon: () => null,
    scanCategories: [],
    navGroups: [],
    policyStats: { totalPolicies: 1, enabledPolicies: 1, disabledPolicies: 0 },
    getCategoryCount: () => 0,
  }),
}));

jest.mock("../components/ScanPolicies/useSecretPolicies", () => ({
  useSecretPolicies: () => ({
    policies: {},
    handlePolicyToggle: secretToggle,
    handleBulkToggle: jest.fn(),
    policyStats: { totalPolicies: 0, enabledPolicies: 0, disabledPolicies: 0 },
    getCategoryCount: () => 0,
    getSeverityColor: () => "red",
    getSeverityIcon: () => null,
  }),
}));

jest.mock("../components/ScanPolicies/ScanPoliciesSidebar", () => ({
  ScanPoliciesSidebar: () => <div data-testid="sidebar" />,
}));

jest.mock("../components/ScanPolicies/MobileMenu", () => ({
  MobileMenu: () => <div data-testid="mobile-menu" />,
}));

jest.mock("../components/ScanPolicies/ScanPoliciesList", () =>
  function MockList({ onPolicyToggle }) {
    return (
      <button type="button" onClick={() => onPolicyToggle("policy-1")}>
        toggle policy
      </button>
    );
  },
);

describe("KAN-58 policy UI gates match backend capability", () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it("member sees read-only notice and cannot dispatch a policy write", () => {
    render(<ScanPoliciesCard orgName="acme" canEdit={false} />);

    expect(screen.getByText(/read-only/i)).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: /toggle policy/i }));

    expect(scanToggle).not.toHaveBeenCalled();
    expect(secretToggle).not.toHaveBeenCalled();
    expect(toastInfo).toHaveBeenCalledWith(
      "Only organization admins can change scan policies",
    );
  });

  it("admin has no read-only notice and policy writes reach the handler", () => {
    render(<ScanPoliciesCard orgName="acme" canEdit />);

    expect(screen.queryByText(/read-only/i)).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: /toggle policy/i }));

    expect(scanToggle).toHaveBeenCalledWith("policy-1");
    expect(toastInfo).not.toHaveBeenCalled();
  });
});

describe("KAN-58 scan options gates", () => {
  beforeEach(() => {
    jest.clearAllMocks();
    global.fetch = jest.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ scanConfigurations: { workflow: true } }),
    });
  });

  it("member toggles are disabled and never PUT to the admin-only route", async () => {
    render(<ScanOptionsCard isAdmin={false} orgName="acme" />);

    await waitFor(() => {
      expect(global.fetch).toHaveBeenCalled();
    });

    const mutating = global.fetch.mock.calls.filter(
      ([, options]) => options?.method && options.method !== "GET",
    );
    expect(mutating).toHaveLength(0);
  });
});
