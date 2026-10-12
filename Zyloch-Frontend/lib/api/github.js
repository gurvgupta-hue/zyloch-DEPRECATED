"use client";

const API_BASE_URL = `${process.env.NEXT_PUBLIC_API_URL}/api`;

async function fetchAPI(endpoint, options = {}) {
  if (typeof endpoint !== "string" || !endpoint.startsWith("/")) {
    throw new Error("Invalid API endpoint");
  }

  const res = await fetch(`${API_BASE_URL}${endpoint}`, {
    ...options,
    credentials: "include",
    headers: {
      "Content-Type": "application/json",
      ...(options.headers || {}),
    },
  });

  if (!res.ok) {
    const data = await res.json().catch(() => ({}));
    const error = new Error(data?.message || data?.error || `HTTP error ${res.status}`);
    // The API answers some refusals with a machine-readable reason. The one that
    // matters here is REPO_SELECTION_REQUIRED, which the dashboard turns into the
    // repository chooser rather than an error card — so it must survive the throw.
    error.status = res.status;
    if (data?.code) error.code = data.code;
    if (data?.selection) error.selection = data.selection;
    throw error;
  }

  return res.json().catch(() => null);
}

export const getInstallations = () => fetchAPI("/installations");

export const checkUserInstallation = async () => {
  const data = await fetchAPI("/installations/check-status");
  return data?.hasInstallation ?? false;
};

// Whether one specific installation has been recorded and is visible to this user.
export const checkInstallationLinked = async (installationId) => {
  const data = await fetchAPI(
    `/installations/check-status?installationId=${encodeURIComponent(installationId)}`
  );
  return data?.linked === true;
};


export const getRepositories = (installationId) =>
  fetchAPI(`/installations/${installationId}/repos`);

export const getRepositoriesFromDB = (installationId, repositoryName = null) => {
  const query = repositoryName
    ? `?repositoryName=${encodeURIComponent(repositoryName)}`
    : "";
  return fetchAPI(`/repositories/${installationId}${query}`);
};

export const getBranchesFromDB = (installationId, repositoryName) =>
  fetchAPI(
    `/repositories/${installationId}/${encodeURIComponent(
      repositoryName
    )}/branches`
  );

export const getBranches = (installationId, owner, repo) =>
  fetchAPI(
    `/installations/${installationId}/repos/${encodeURIComponent(
      owner
    )}/${encodeURIComponent(repo)}/branches`
  );

export const getInstallationSummary = (installationId) =>
  fetchAPI(`/installations/${installationId}/summary`);

export const startInstallationSummary = (
  installationId,
  forceRefresh = false
) =>
  fetchAPI(
    `/installation-summary/${installationId}/start${
      forceRefresh ? "?forceRefresh=true" : ""
    }`,
    { method: "POST" }
  );

export const refreshInstallationData = (
  installationId,
  forceRefresh = false
) =>
  fetchAPI(
    `/installation-summary/${installationId}/refresh${
      forceRefresh ? "?forceRefresh=true" : ""
    }`,
    { method: "POST" }
  );

export const pollInstallationSummary = (jobId) =>
  fetchAPI(`/installation-summary/status/${jobId}`);

export const retryFailedJob = (jobId) =>
  fetchAPI(`/installation-summary/retry/${jobId}`, { method: "POST" });

// --- Repository selection (installations over the plan's repo limit) ----------

export const getRepoSelection = (installationId) =>
  fetchAPI(`/installations/${installationId}/repo-selection`);

export const listSelectableRepos = (
  installationId,
  { q = "", page = 1, perPage = 50, sort = "active", filter = "all" } = {}
) => {
  const params = new URLSearchParams({
    page: String(page),
    perPage: String(perPage),
    sort,
    filter,
  });
  if (q) params.set("q", q);
  return fetchAPI(`/installations/${installationId}/repo-selection/repos?${params}`);
};

export const saveRepoSelection = (installationId, repos) =>
  fetchAPI(`/installations/${installationId}/repo-selection`, {
    method: "POST",
    body: JSON.stringify({ repos }),
  });

export const autoSelectRepos = (installationId) =>
  fetchAPI(`/installations/${installationId}/repo-selection/auto`, { method: "POST" });

export const syncRepoCatalog = (installationId) =>
  fetchAPI(`/installations/${installationId}/repo-selection/sync`, { method: "POST" });
