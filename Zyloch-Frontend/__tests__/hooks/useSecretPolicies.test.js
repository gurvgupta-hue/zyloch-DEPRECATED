import { renderHook, act, waitFor } from "@testing-library/react";
import { useSecretPolicies } from "@/app/settings/components/ScanPolicies/useSecretPolicies";

jest.mock("@/data/secretDetection.json", () => ({
  __esModule: true,
  default: {
    detections: [
      {
        title: "OpenAI API Key",
        severity: "critical",
        category: "Credentials and Tokens",
        infoTypes: ["openai_api_key"],
        finding: "Exposed OpenAI API key.",
        recommendation: "Rotate the key immediately.",
      },
      {
        title: "GitHub Token",
        severity: "high",
        category: "Credentials and Tokens",
        infoTypes: ["github_token"],
        finding: "Exposed GitHub token.",
        recommendation: "Revoke and regenerate the token.",
      },
      {
        title: "Credit Card Number",
        severity: "high",
        category: "PCI and Financial Data",
        infoTypes: ["CREDIT_CARD_NUMBER"],
        finding: "Exposed credit card number.",
        recommendation: "Remove the number from the codebase.",
      },
      {
        title: "Passport Number",
        severity: "high",
        category: "Sensitive PII",
        infoTypes: ["CHINA_PASSPORT"],
        finding: "Exposed passport number.",
        recommendation: "Remove the number from the codebase.",
      },
    ],
  },
}));

jest.mock("@/components/common/TechIcon.js", () => ({
  __esModule: true,
  default: () => null,
}));

jest.mock("lucide-react", () => ({
  AlertTriangle: () => null,
  AlertCircle: () => null,
  Info: () => null,
}));

// MT-08: policy config now goes through the tenant-scoped backend. The tenant
// comes from the session cookie, so no org name appears in the URL.
const POLICIES_URL = `${process.env.NEXT_PUBLIC_API_URL}/api/organization/policies`;

const makeConfigResponse = (disabled = {}) => ({
  ok: true,
  json: async () => ({
    success: true,
    scanners: { secret_scanner: { policies: disabled } },
  }),
});

describe("useSecretPolicies", () => {
  beforeEach(() => {
    jest.clearAllMocks();
    global.fetch = jest.fn().mockResolvedValue({ ok: true, json: async () => ({}) });
  });

  test("initializes all policies as enabled", () => {
    const { result } = renderHook(() => useSecretPolicies({}));

    const allEnabled = Object.values(result.current.policies)
      .flat()
      .every((p) => p.enabled === true);

    expect(allEnabled).toBe(true);
  });

  test("buckets openai_api_key into api-keys", () => {
    const { result } = renderHook(() => useSecretPolicies({}));
    expect(result.current.policies["api-keys"].some((p) => p.id === "openai_api_key")).toBe(true);
  });

  test("buckets github_token into access-tokens", () => {
    const { result } = renderHook(() => useSecretPolicies({}));
    expect(result.current.policies["access-tokens"].some((p) => p.id === "github_token")).toBe(true);
  });

  test("buckets CREDIT_CARD_NUMBER into dlp-pci", () => {
    const { result } = renderHook(() => useSecretPolicies({}));
    expect(result.current.policies["dlp-pci"].some((p) => p.id === "CREDIT_CARD_NUMBER")).toBe(true);
  });

  test("buckets CHINA_PASSPORT into dlp-pii", () => {
    const { result } = renderHook(() => useSecretPolicies({}));
    expect(result.current.policies["dlp-pii"].some((p) => p.id === "CHINA_PASSPORT")).toBe(true);
  });

  test("toggles a policy on/off", () => {
    const { result } = renderHook(() => useSecretPolicies({}));

    act(() => {
      result.current.handlePolicyToggle("openai_api_key", "api-keys");
    });

    const policy = result.current.policies["api-keys"].find((p) => p.id === "openai_api_key");
    expect(policy.enabled).toBe(false);
  });

  test("bulk toggles all policies in a subcategory", () => {
    const { result } = renderHook(() => useSecretPolicies({}));

    act(() => {
      result.current.handleBulkToggle("api-keys", false);
    });

    expect(result.current.policies["api-keys"].every((p) => p.enabled === false)).toBe(true);
  });

  test("calculates policy statistics correctly", () => {
    const { result } = renderHook(() => useSecretPolicies({}));

    expect(result.current.policyStats.totalPolicies).toBe(4);
    expect(result.current.policyStats.enabledPolicies).toBe(4);
    expect(result.current.policyStats.enabledPercentage).toBe(100);
  });

  test("returns severity color based on severity level", () => {
    const { result } = renderHook(() => useSecretPolicies({}));

    expect(result.current.getSeverityColor("CRITICAL")).toContain("danger");
    expect(result.current.getSeverityColor("HIGH")).toContain("warning");
    expect(result.current.getSeverityColor("MEDIUM")).toContain("accent");
  });

  test("loads config without needing an orgName (tenant comes from the session)", async () => {
    global.fetch.mockResolvedValueOnce(makeConfigResponse({ openai_api_key: false }));

    const { result } = renderHook(() => useSecretPolicies({}));

    await waitFor(() => {
      const policy = result.current.policies["api-keys"].find((p) => p.id === "openai_api_key");
      expect(policy.enabled).toBe(false);
    });

    expect(global.fetch).toHaveBeenCalledWith(
      POLICIES_URL,
      expect.objectContaining({ credentials: "include" })
    );
  });

  test("loads saved config from API", async () => {
    global.fetch.mockResolvedValueOnce(makeConfigResponse({ openai_api_key: false }));

    const { result } = renderHook(() => useSecretPolicies({ orgName: "test-org" }));

    await waitFor(() => {
      const policy = result.current.policies["api-keys"].find((p) => p.id === "openai_api_key");
      expect(policy.enabled).toBe(false);
    });
  });

  test("saves changes to the tenant-scoped API, scoped to this scanner only", async () => {
    global.fetch
      .mockResolvedValueOnce(makeConfigResponse())
      .mockResolvedValueOnce({ ok: true, json: async () => ({}) });

    const { result } = renderHook(() => useSecretPolicies({ orgName: "test-org" }));

    await waitFor(() => {
      expect(global.fetch).toHaveBeenCalledTimes(1);
    });

    act(() => {
      result.current.handlePolicyToggle("openai_api_key", "api-keys");
    });

    await act(async () => {
      await result.current.savePreferences();
    });

    expect(global.fetch).toHaveBeenCalledTimes(2);
    const putCall = global.fetch.mock.calls.find((call) => call[1]?.method === "PUT");
    expect(putCall).toBeDefined();
    expect(putCall[0]).toBe(POLICIES_URL);
    expect(putCall[1].credentials).toBe("include");

    // Only the secret scanner key is sent, so saving here cannot clobber the
    // IaC panel's toggles (MT-08).
    const body = JSON.parse(putCall[1].body);
    expect(Object.keys(body.scanners)).toEqual(["secret_scanner"]);
    expect(body.scanners.secret_scanner.policies.openai_api_key).toBe(false);
  });

  test("handles fetch error gracefully during load", async () => {
    const consoleSpy = jest.spyOn(console, "error").mockImplementation(() => {});
    global.fetch.mockRejectedValueOnce(new TypeError("Failed to fetch"));

    renderHook(() => useSecretPolicies({ orgName: "test-org" }));

    await waitFor(() => {
      expect(consoleSpy).toHaveBeenCalledWith(
        "Error loading secret policy config:",
        expect.any(TypeError)
      );
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

    const { result } = renderHook(() => useSecretPolicies({ orgName: "test-org" }));

    await act(async () => {
      result.current.handlePolicyToggle("openai_api_key", "api-keys");
    });

    await expect(result.current.savePreferences()).rejects.toThrow();
  });

  test("getCategoryCount returns correct total for nested category", () => {
    const { result } = renderHook(() => useSecretPolicies({}));
    const category = { subCategories: [{ id: "api-keys" }, { id: "access-tokens" }] };

    expect(result.current.getCategoryCount(category)).toBe(
      result.current.policies["api-keys"].length +
        result.current.policies["access-tokens"].length
    );
  });
});