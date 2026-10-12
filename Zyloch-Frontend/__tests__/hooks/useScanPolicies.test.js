import { renderHook, act, waitFor } from "@testing-library/react";
import { useScanPolicies } from "@/app/settings/components/ScanPolicies/useScanPolicies";

// Mock data
jest.mock("@/data/scanPoliciesData", () => ({
  __esModule: true,
  default: {
    workflow: [
      { code: "WF-001", name: "Checkout Security", severity: "high", description: "test" },
      { code: "WF-002", name: "Artifact Verification", severity: "critical", description: "test" },
    ],
    kubernetes: [
      { code: "K8S-001", name: "Privileged Containers", severity: "high", description: "test" },
    ],
    docker: [
      { code: "DOCKER-001", name: "Latest Tag", severity: "low", description: "test" },
    ],
    terraform: [
      { code: "AWS-SEC-001", name: "AWS RDS Encryption", severity: "critical", description: "test" },
      { code: "AZ-SEC-001", name: "Azure Storage HTTPS", severity: "high", description: "test" },
      { code: "GCP-SEC-001", name: "GCP Bucket Access", severity: "medium", description: "test" },
    ],
  },
}));

jest.mock("@/components/common/TechIcon.js", () => () => null);
jest.mock("lucide-react", () => ({
  AlertTriangle: () => null,
  AlertCircle: () => null,
  Info: () => null,
}));

const API_URL = "http://localhost:8000";
process.env.NEXT_PUBLIC_SCAN_API_URL = API_URL;

// MT-08: policy config goes through the tenant-scoped backend; the tenant comes
// from the session cookie, so no org name appears in the URL.
const POLICIES_URL = `${process.env.NEXT_PUBLIC_API_URL}/api/organization/policies`;

describe("useScanPolicies", () => {
  beforeEach(() => {
    jest.clearAllMocks();
    global.fetch = jest.fn().mockResolvedValue({ ok: true, json: async () => ({}) });
  });

  test("initializes all policies as enabled", () => {
    const { result } = renderHook(() => useScanPolicies({}));
    
    const allEnabled = Object.values(result.current.policies)
      .flat()
      .every(p => p.enabled === true);
    
    expect(allEnabled).toBe(true);
  });

  test("initializes AWS policies from terraform data", () => {
    const { result } = renderHook(() => useScanPolicies({}));
    
    expect(result.current.policies.aws).toHaveLength(1);
    expect(result.current.policies.aws[0].name).toBe("AWS RDS Encryption");
  });

  test("toggles a policy on/off", () => {
    const { result } = renderHook(() => useScanPolicies({}));
    
    act(() => {
      result.current.handlePolicyToggle("WF-001", "workflow");
    });
    
    const policy = result.current.policies.workflow.find(p => p.id === "WF-001");
    expect(policy.enabled).toBe(false);
  });

  test("bulk toggles all policies in a category", () => {
    const { result } = renderHook(() => useScanPolicies({}));
    
    act(() => {
      result.current.handleBulkToggle("workflow", false);
    });
    
    const allDisabled = result.current.policies.workflow.every(p => p.enabled === false);
    expect(allDisabled).toBe(true);
  });

  test("changes policy severity", () => {
    const { result } = renderHook(() => useScanPolicies({}));
    
    act(() => {
      result.current.handleSeverityChange("WF-001", "workflow", "CRITICAL");
    });
    
    const policy = result.current.policies.workflow.find(p => p.id === "WF-001");
    expect(policy.severity).toBe("CRITICAL");
  });

  test("calculates policy statistics correctly (excluding terraform)", () => {
    const { result } = renderHook(() => useScanPolicies({}));
    
    // workflow(2) + kubernetes(1) + docker(1) + aws(1) + azure(1) + gcp(1) = 7
    expect(result.current.policyStats.totalPolicies).toBe(7);
    expect(result.current.policyStats.enabledPolicies).toBe(7);
  });

  test("counts policies in a category with nested subcategories", () => {
    const { result } = renderHook(() => useScanPolicies({}));
    
    const iacCategory = result.current.scanCategories.find(c => c.id === "iac");
    const count = result.current.getCategoryCount(iacCategory);
    
    expect(count).toBe(5); // Kubernetes(1) + Docker(1) + Terraform AWS/Azure/GCP (3)
  });

  test("collapses/expands categories", () => {
    const { result } = renderHook(() => useScanPolicies({}));
    
    expect(result.current.expandedCategories).toContain("workflow");
    
    act(() => {
      result.current.toggleCategory("workflow");
    });
    
    expect(result.current.expandedCategories).not.toContain("workflow");
  });

  test("loads saved config from the tenant-scoped API", async () => {
    global.fetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        scanners: { workflow: { policies: { "WF-001": false } } }
      })
    });
    
    const { result } = renderHook(() => useScanPolicies({ orgName: "test-org" }));
    
    await waitFor(() => {
      const policy = result.current.policies.workflow.find(p => p.id === "WF-001");
      expect(policy.enabled).toBe(false);
    });

    expect(global.fetch).toHaveBeenCalledWith(
      POLICIES_URL,
      expect.objectContaining({ credentials: "include" })
    );
  });

  test("saves changes to the tenant-scoped API", async () => {
    global.fetch
      .mockResolvedValueOnce({ ok: true, json: async () => ({}) })
      .mockResolvedValueOnce({ ok: true, json: async () => ({}) });
    
    const { result } = renderHook(() => useScanPolicies({ orgName: "test-org" }));
    
    await act(async () => {
      result.current.handlePolicyToggle("WF-001", "workflow");
      await result.current.savePreferences();
    });
    
    expect(global.fetch).toHaveBeenCalledTimes(2);
    const putCall = global.fetch.mock.calls.find(call => call[1]?.method === "PUT");
    expect(putCall).toBeDefined();
    expect(putCall[0]).toBe(POLICIES_URL);
    expect(putCall[1].credentials).toBe("include");
    // Sends a scanner-keyed merge payload, not a whole-document replace.
    expect(JSON.parse(putCall[1].body)).toHaveProperty("scanners.workflow");
  });

  test("handles fetch error gracefully during load", async () => {
    const consoleSpy = jest.spyOn(console, "error").mockImplementation(() => {});
    global.fetch.mockRejectedValueOnce(new TypeError("Failed to fetch"));
    
    renderHook(() => useScanPolicies({ orgName: "test-org" }));
    
    await waitFor(() => {
      expect(consoleSpy).toHaveBeenCalledWith("Error loading IaC policy config:", expect.any(TypeError));
    });
    consoleSpy.mockRestore();
  });

  // Kept from main, with the assertion updated to the MT-08.4 contract: a failed
  // save must NOT be swallowed. It previously logged and returned, which left the
  // panel showing toggles that were never persisted; it now propagates so the
  // caller can surface it.
  test("propagates a save failure instead of swallowing it", async () => {
    global.fetch
      .mockResolvedValueOnce({ ok: true, json: async () => ({}) })
      .mockRejectedValueOnce(new TypeError("Failed to fetch"));

    const { result } = renderHook(() => useScanPolicies({ orgName: "test-org" }));

    await act(async () => {
      result.current.handlePolicyToggle("WF-001", "workflow");
    });

    await expect(result.current.savePreferences()).rejects.toThrow();
  });
});