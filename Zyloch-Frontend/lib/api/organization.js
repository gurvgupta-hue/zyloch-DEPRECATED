import { toast } from 'react-toastify';

const API_URL = process.env.NEXT_PUBLIC_API_URL;

async function orgRequest(path, options = {}, showToast = true) {
  try {
    const res = await fetch(`${API_URL}${path}`, {
      credentials: 'include',
      headers: { 'Content-Type': 'application/json', ...(options.headers || {}) },
      ...options,
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      if (showToast) toast.error(data.message || `Request failed (${res.status})`);
      const err = new Error(data.message || `HTTP ${res.status}`);
      err.status = res.status;
      err.data = data;
      throw err;
    }
    return data;
  } catch (err) {
    if (showToast && !err.status) toast.error('Network error');
    throw err;
  }
}

export async function getOrganization(showToast = false) {
  const data = await orgRequest('/api/organization', { method: 'GET' }, showToast);
  return data.organization;
}

/**
 * Effective RBAC capabilities for the signed-in user (KAN-58).
 * Mirrors Zyloch-Backend/services/rbac.js so UI gates match backend guards.
 */
export async function getCapabilities(showToast = false) {
  const data = await orgRequest('/api/organization/capabilities', { method: 'GET' }, showToast);
  return {
    role: data.role || null,
    isAdmin: !!data.isAdmin,
    capabilities: data.capabilities || {},
  };
}

export async function getLicense(showToast = false) {
  const data = await orgRequest('/api/organization/license', { method: 'GET' }, showToast);
  return data.license;
}

export async function listMembers(showToast = false) {
  const data = await orgRequest('/api/organization/members', { method: 'GET' }, showToast);
  return data;
}

export async function inviteMember(email, showToast = true) {
  return orgRequest(
    '/api/organization/members/invite',
    { method: 'POST', body: JSON.stringify({ email }) },
    showToast
  );
}

export async function deactivateMember(userId, showToast = true) {
  return orgRequest(
    `/api/organization/members/${userId}/deactivate`,
    { method: 'POST' },
    showToast
  );
}

export async function reactivateMember(userId, showToast = true) {
  return orgRequest(
    `/api/organization/members/${userId}/reactivate`,
    { method: 'POST' },
    showToast
  );
}

export async function deleteMember(userId, showToast = true) {
  return orgRequest(
    `/api/organization/members/${userId}`,
    { method: 'DELETE' },
    showToast
  );
}

export async function revokeInvite(inviteId, showToast = true) {
  return orgRequest(
    `/api/organization/members/invites/${inviteId}/revoke`,
    { method: 'POST' },
    showToast
  );
}

/**
 * Per-scanner policy toggles for the signed-in tenant (MT-08).
 *
 * These replace direct browser calls to the scanner service, which carried no
 * tenant context or credentials and therefore always failed. The tenant is
 * resolved server-side from the session.
 */
export async function getPolicyConfigurations(showToast = false) {
  const data = await orgRequest('/api/organization/policies', { method: 'GET' }, showToast);
  return data.scanners || {};
}

/**
 * Merge-update policy toggles. Only the scanner keys passed are modified, so
 * independent settings panels do not overwrite each other.
 * @param {Record<string, { policies?: object, enabled?: boolean }>} scanners
 */
export async function updatePolicyConfigurations(scanners, showToast = true) {
  const data = await orgRequest(
    '/api/organization/policies',
    { method: 'PUT', body: JSON.stringify({ scanners }) },
    showToast
  );
  return data.scanners || {};
}

export async function listMyOrganizations(showToast = false) {
  const data = await orgRequest('/auth/organizations', { method: 'GET' }, showToast);
  return data.organizations || [];
}

export async function switchOrganization(tenantId, showToast = true) {
  return orgRequest(
    '/auth/switch-organization',
    { method: 'POST', body: JSON.stringify({ tenantId }) },
    showToast
  );
}
