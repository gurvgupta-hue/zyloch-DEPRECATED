const ORG_LOGIN_STORAGE_KEY = "xylogOrgLoginId";

function extractOrganizationId(user) {
  const org = user?.organizationId;

  if (!org) return null;
  if (typeof org === "string") return org;
  if (typeof org === "object") {
    return org._id || org.id || null;
  }

  return null;
}

export function persistOrgLoginId(orgId) {
  if (typeof window === "undefined") return;

  if (orgId) {
    localStorage.setItem(ORG_LOGIN_STORAGE_KEY, orgId);
    return;
  }

  localStorage.removeItem(ORG_LOGIN_STORAGE_KEY);
}

export function getStoredOrgLoginId() {
  if (typeof window === "undefined") return null;
  return localStorage.getItem(ORG_LOGIN_STORAGE_KEY);
}

export function getLoginRedirectPathFromOrgId(orgId) {
  if (!orgId) return "/login";
  return `/login?org_id=${encodeURIComponent(orgId)}`;
}

export function getPostLogoutRedirectPath(user) {
  if (user?.role === "member") {
    const orgId = extractOrganizationId(user) || getStoredOrgLoginId();
    return getLoginRedirectPathFromOrgId(orgId);
  }

  return "/login";
}

export function getPostLockoutRedirectPath() {
  return getLoginRedirectPathFromOrgId(getStoredOrgLoginId());
}
