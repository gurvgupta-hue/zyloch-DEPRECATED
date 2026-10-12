/** @jest-environment node */

const API_URL = "http://localhost:5000";

describe("lib/api/scans BFF client", () => {
  const originalFetch = global.fetch;

  beforeEach(() => {
    process.env.NEXT_PUBLIC_API_URL = API_URL;
    jest.resetModules();
    global.fetch = jest.fn();
  });

  afterEach(() => {
    global.fetch = originalFetch;
    delete process.env.NEXT_PUBLIC_API_URL;
  });

  it("startScan calls backend BFF with cookie auth and installationId", async () => {
    global.fetch.mockResolvedValue({
      ok: true,
      status: 200,
      statusText: "OK",
      json: async () => ({ message: "Scan initiated" }),
    });

    const { startScan } = require("@/lib/api/scans");
    await startScan(9001, "acme-org", "api", "main", "docker");

    expect(global.fetch).toHaveBeenCalledTimes(1);
    const [url, options] = global.fetch.mock.calls[0];
    expect(url).toBe(`${API_URL}/api/scans`);
    expect(options.method).toBe("POST");
    expect(options.credentials).toBe("include");
    expect(JSON.parse(options.body)).toMatchObject({
      installationId: "9001",
      org_name: "acme-org",
      repo_name: "api",
      branch: "main",
      scan_type: "docker",
    });
  });

  it("startScan normalizes frontend scanner names to backend canonical keys", async () => {
    global.fetch.mockResolvedValue({
      ok: true,
      status: 200,
      statusText: "OK",
      json: async () => ({ message: "Scan initiated" }),
    });

    const { startScan } = require("@/lib/api/scans");

    // secret-scanner -> secret_scanner
    await startScan(9001, "acme-org", "api", "main", "secret-scanner");
    expect(JSON.parse(global.fetch.mock.calls[0][1].body).scan_type).toBe("secret_scanner");

    // spec_scanner -> spec-scanner
    await startScan(9001, "acme-org", "api", "main", "spec_scanner");
    expect(JSON.parse(global.fetch.mock.calls[1][1].body).scan_type).toBe("spec-scanner");

    // skill_scanner -> skill-scanner
    await startScan(9001, "acme-org", "api", "main", "skill_scanner");
    expect(JSON.parse(global.fetch.mock.calls[2][1].body).scan_type).toBe("skill-scanner");

    // cis_agent -> cis-agent
    await startScan(9001, "acme-org", "api", "main", "cis_agent");
    expect(JSON.parse(global.fetch.mock.calls[3][1].body).scan_type).toBe("cis-agent");

    // cfn -> cloudformation
    await startScan(9001, "acme-org", "api", "main", "cfn");
    expect(JSON.parse(global.fetch.mock.calls[4][1].body).scan_type).toBe("cloudformation");
  });

  it("getLatestScan calls backend BFF latest endpoint", async () => {
    global.fetch.mockResolvedValue({
      ok: true,
      status: 200,
      statusText: "OK",
      json: async () => ({ scan_id: "scan-1" }),
    });

    const { getLatestScan } = require("@/lib/api/scans");
    await getLatestScan(9001, "acme-org", "api", "main", "docker");

    const [url, options] = global.fetch.mock.calls[0];
    expect(url).toContain(`${API_URL}/api/scans/latest?`);
    expect(url).toContain("installationId=9001");
    expect(url).toContain("org_name=acme-org");
    expect(options.credentials).toBe("include");
  });

  it("getScan calls backend BFF detail endpoint", async () => {
    global.fetch.mockResolvedValue({
      ok: true,
      status: 200,
      statusText: "OK",
      json: async () => ({ scan_id: "scan-1" }),
    });

    const { getScan } = require("@/lib/api/scans");
    await getScan("scan-1", 9001);

    const [url] = global.fetch.mock.calls[0];
    expect(url).toContain(`${API_URL}/api/scans/scan-1?`);
    expect(url).toContain("installationId=9001");
  });

  it("does not use NEXT_PUBLIC_SCAN_API_URL", () => {
    process.env.NEXT_PUBLIC_SCAN_API_URL = "http://ghapp-host:8000";
    const scansModule = require("@/lib/api/scans");
    expect(scansModule).toBeTruthy();
    expect(global.fetch).not.toHaveBeenCalled();
  });
});
