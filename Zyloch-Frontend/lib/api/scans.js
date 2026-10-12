const API_BASE = (process.env.NEXT_PUBLIC_API_URL || "").replace(/\/$/, "");
const SCANS_BASE = `${API_BASE}/api/scans`;

const responseCache = new Map();
const CACHE_TTL = 30000;

const BACKEND_SCAN_TYPE_MAP = {
  "secret-scanner": "secret_scanner",
  "secret_scanner": "secret_scanner",
  "spec_scanner": "spec-scanner",
  "spec-scanner": "spec-scanner",
  "skill_scanner": "skill-scanner",
  "skill-scanner": "skill-scanner",
  "ai-security-scanner": "skill-scanner",
  "cis_agent": "cis-agent",
  "cis-agent": "cis-agent",
  "cfn": "cloudformation",
  "cloudformation": "cloudformation",
};

function normalizeScanType(scanType) {
  const value = String(scanType || "").trim();
  if (!value) return value;

  const lower = value.toLowerCase();

  return BACKEND_SCAN_TYPE_MAP[lower] || value;
}

function requireInstallationId(installationId) {
  const value = String(installationId || "").trim();
  if (!value) {
    throw new Error("installationId is required");
  }
  return value;
}

function parseErrorMessage(data, response) {
  if (data?.message) return data.message;
  if (typeof data?.detail === "string") return data.detail;
  if (Array.isArray(data?.detail)) {
    return data.detail.map((err) => err.msg || err.message).join(", ");
  }
  if (data?.error) return data.error;
  return `HTTP ${response.status}: ${response.statusText}`;
}

async function apiFetch(url, options = {}) {
  if (!API_BASE) {
    throw new Error("NEXT_PUBLIC_API_URL is not configured");
  }

  const bypassCache = Boolean(options.bypassCache) || options.method === "POST" || options.method === "PUT" || options.method === "DELETE";
  const method = options.method || "GET";
  const cacheKey = (!bypassCache && method === "GET") ? `${url}-${JSON.stringify(options)}` : null;

  if (cacheKey && responseCache.has(cacheKey)) {
    const cached = responseCache.get(cacheKey);
    if (Date.now() - cached.timestamp < CACHE_TTL) {
      return cached.data;
    }
    responseCache.delete(cacheKey);
  }

  const fetchOptions = { ...options };
  delete fetchOptions.bypassCache;
  const config = {
    ...fetchOptions,
    method,
    credentials: "include",
    headers: {
      "Content-Type": "application/json",
      ...(options.headers || {}),
    },
  };

  if (options.body && typeof options.body === "object") {
    config.body = JSON.stringify(options.body);
  }

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 90000);
    config.signal = controller.signal;

    const response = await fetch(url, config);
    clearTimeout(timeoutId);

    const data = await response.json().catch(() => ({}));

    if (!response.ok) {
      const error = new Error(parseErrorMessage(data, response));
      error.status = response.status;
      throw error;
    }

    if (cacheKey) {
      responseCache.set(cacheKey, {
        data,
        timestamp: Date.now(),
      });
    }

    return data;
  } catch (error) {
    if (error.name === "AbortError") {
      throw new Error("Request timeout: The server took too long to respond");
    }

    throw new Error(
      error instanceof Error ? error.message : `Network error: ${error}`
    );
  }
}

export function clearCache(pattern = "") {
  if (!pattern) return responseCache.clear();

  for (const key of responseCache.keys()) {
    if (key.includes(pattern)) {
      responseCache.delete(key);
    }
  }
}

export async function startScan(
  installationId,
  org,
  repo,
  branch = "main",
  type = "all"
) {
  const scopedInstallationId = requireInstallationId(installationId);
  clearCache();

  return apiFetch(SCANS_BASE, {
    method: "POST",
    body: {
      installationId: scopedInstallationId,
      org_name: String(org),
      repo_name: String(repo),
      branch: String(branch),
      scan_type: normalizeScanType(type),
    },
  });
}

export async function getScans(
  installationId,
  org = null,
  repo = null,
  limit = 50
) {
  const params = new URLSearchParams({
    installationId: requireInstallationId(installationId),
  });

  if (org) params.set("org_name", String(org));
  if (repo) params.set("repo_name", String(repo));
  if (limit) params.set("limit", String(limit));

  return apiFetch(`${SCANS_BASE}?${params}`);
}

export async function getLatestScan(
  installationId,
  org,
  repo,
  branch = "main",
  scanType = null,
  options = {}
) {
  const params = new URLSearchParams({
    installationId: requireInstallationId(installationId),
    org_name: String(org),
    repo_name: String(repo),
    branch: String(branch),
  });

  const normalized = normalizeScanType(scanType);
  if (normalized && normalized !== "all") {
    params.set("scan_type", normalized);
  }

  return apiFetch(`${SCANS_BASE}/latest?${params}`, {
    bypassCache: options.bypassCache,
  });
}

export async function getScan(scanId, installationId, options = {}) {
  const params = new URLSearchParams({
    installationId: requireInstallationId(installationId),
  });

  return apiFetch(
    `${SCANS_BASE}/${encodeURIComponent(String(scanId))}?${params}`,
    { bypassCache: options.bypassCache }
  );
}

/**
 * Autofix (from main) routed through the tenant-guarded backend BFF.
 *
 * These originally called the scan service directly. Under multi-tenancy every
 * scan-surface call goes through `/api/scans/*`, which applies auth + tenantGuard
 * + capability checks and verifies the installation belongs to the caller's
 * tenant — so `installationId` is required here as it is on every other call.
 */
export async function requestAutofix(
  finding,
  { forceRefresh = false, installationId } = {}
) {
  return apiFetch(`${SCANS_BASE}/ai/autofix`, {
    method: "POST",
    body: {
      installationId: requireInstallationId(installationId),
      policy_code: finding?.policyCode || null,
      policy_name: finding?.policyName || null,
      description: finding?.description || "",
      severity: finding?.severity || null,
      file: finding?.file || finding?.fullPath || null,
      line: finding?.lineNo || null,
      scanner_type: finding?.scannerType || finding?.type || null,
      code_block: finding?.codeBlock || "",
      sbom_context: finding?.sbomContext || null,
      force_refresh: forceRefresh,
    },
  });
}

export async function createAutofixPr(finding, proposal, repositoryContext) {
  return apiFetch(`${SCANS_BASE}/ai/autofix/pr`, {
    method: "POST",
    body: {
      installationId: requireInstallationId(repositoryContext?.installationId),
      repository: String(repositoryContext?.repository ?? ""),
      branch: String(repositoryContext?.branch ?? "main"),
      file: String(finding?.file || finding?.fullPath || ""),
      code_block: String(finding?.codeBlock ?? ""),
      proposal: String(proposal ?? ""),
    },
  });
}
