const axios = require('axios');

/**
 * Feature flag: when true, list/check installation APIs only return GitHub orgs
 * the authenticated user is a member of (KAN-51).
 */
function isEnforceGithubMembership(env = process.env) {
  return String(env.ENFORCE_GITHUB_MEMBERSHIP || '').toLowerCase() === 'true';
}

/**
 * Check whether `username` is a member of the GitHub org (or owns the user install).
 * Uses the App installation token so we do not depend on a stored user OAuth token.
 *
 * @returns {Promise<boolean>}
 */
async function isGithubOrgMember(
  { orgLogin, accountType, username, installationId },
  deps = {}
) {
  const login = String(username || '').trim();
  const org = String(orgLogin || '').trim();
  if (!login || !org) return false;

  if (String(accountType || '').toLowerCase() === 'user') {
    return login.toLowerCase() === org.toLowerCase();
  }

  const getToken =
    deps.getInstallationToken ||
    require('./githubTokenHelper').getInstallationToken;
  const httpGet = deps.axiosGet || ((url, opts) => axios.get(url, opts));

  try {
    const token = await getToken(Number(installationId));
    const url = `https://api.github.com/orgs/${encodeURIComponent(org)}/members/${encodeURIComponent(login)}`;
    const res = await httpGet(url, {
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: 'application/vnd.github+json',
      },
      timeout: 15000,
      maxRedirects: 0,
      validateStatus: (status) => status === 204 || status === 404 || status === 302,
    });
    // 204 = member; 302 = public membership redirect without auth context (treat as member)
    return res.status === 204 || res.status === 302;
  } catch (err) {
    const status = err.response?.status;
    if (status === 404) return false;
    // Network / permission errors: fail open so a flaky GitHub API does not blank the UI.
    console.warn('[GitHubMembership] check failed; allowing install through', {
      org,
      username: login,
      installationId,
      status,
      message: err.message,
    });
    return true;
  }
}

/**
 * Filter tenant installations to those the GitHub user may access.
 * No-op when ENFORCE_GITHUB_MEMBERSHIP is off.
 */
async function filterInstallationsByGithubMembership(installations, username, deps = {}) {
  if (!isEnforceGithubMembership(deps.env || process.env)) {
    return installations;
  }
  if (!username) return [];

  const check = deps.isGithubOrgMember || isGithubOrgMember;
  const results = await Promise.all(
    (installations || []).map(async (inst) => {
      const ok = await check(
        {
          orgLogin: inst.account?.login,
          accountType: inst.account?.type,
          username,
          installationId: inst.installationId,
        },
        deps
      );
      return ok ? inst : null;
    })
  );
  return results.filter(Boolean);
}

/**
 * Read `username`'s membership record on a GitHub org via the App installation token.
 *
 * @returns {Promise<{ state: string|null, role: string|null }|null>} null when the
 *          user has no membership (404) or the App cannot read it (403).
 */
async function getGithubOrgMembershipRole(
  { orgLogin, username, installationId },
  deps = {}
) {
  const getToken =
    deps.getInstallationToken ||
    require('./githubTokenHelper').getInstallationToken;
  const httpGet = deps.axiosGet || ((url, opts) => axios.get(url, opts));

  const token = await getToken(Number(installationId));
  const url = `https://api.github.com/orgs/${encodeURIComponent(orgLogin)}/memberships/${encodeURIComponent(username)}`;
  const res = await httpGet(url, {
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: 'application/vnd.github+json',
    },
    timeout: 15000,
    validateStatus: (status) => status === 200 || status === 403 || status === 404,
  });

  if (res.status !== 200) return null;
  return { state: res.data?.state || null, role: res.data?.role || null };
}

/**
 * Authorization gate for claiming an unlinked GitHub installation (MT-01).
 *
 * Deliberately NOT reusing `isGithubOrgMember`: that helper fails OPEN so a flaky
 * GitHub API cannot blank an already-owned installation list. Claiming binds
 * another account's repositories to a tenant, so every failure path here denies.
 *
 * Bar for approval:
 *   - `User` installs  → the actor must BE that account.
 *   - `Organization`   → the actor must be an ACTIVE ORG ADMIN. Plain membership
 *     is insufficient: any employee could otherwise bind the org's installation
 *     to a personal Zyloch tenant and read every scan result.
 *
 * @returns {Promise<{ allowed: boolean, reason: string }>}
 */
async function verifyInstallationControl(
  { orgLogin, accountType, username, installationId },
  deps = {}
) {
  const login = String(username || '').trim();
  const org = String(orgLogin || '').trim();

  if (!login) return { allowed: false, reason: 'no_github_identity' };
  if (!org) return { allowed: false, reason: 'installation_account_unknown' };

  if (String(accountType || '').toLowerCase() === 'user') {
    return login.toLowerCase() === org.toLowerCase()
      ? { allowed: true, reason: 'personal_account_owner' }
      : { allowed: false, reason: 'not_account_owner' };
  }

  let membership;
  try {
    const readRole = deps.getGithubOrgMembershipRole || getGithubOrgMembershipRole;
    membership = await readRole({ orgLogin: org, username: login, installationId }, deps);
  } catch (err) {
    // Fail closed — an unverifiable claim is a denied claim.
    console.warn('[GitHubMembership] control check errored; denying claim', {
      org,
      username: login,
      installationId,
      status: err.response?.status,
      message: err.message,
    });
    return { allowed: false, reason: 'verification_failed' };
  }

  if (!membership) return { allowed: false, reason: 'not_org_member' };
  if (membership.state !== 'active') return { allowed: false, reason: 'membership_not_active' };
  if (membership.role !== 'admin') return { allowed: false, reason: 'not_org_admin' };

  return { allowed: true, reason: 'org_admin' };
}

module.exports = {
  isEnforceGithubMembership,
  isGithubOrgMember,
  filterInstallationsByGithubMembership,
  getGithubOrgMembershipRole,
  verifyInstallationControl,
};
