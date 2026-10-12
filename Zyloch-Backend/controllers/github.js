const axios = require("axios");
const createError = require("../utils/createError");
const { getInstallationToken } = require("../helpers/githubTokenHelper");
const tenantScope = require("../helpers/tenantScope");
const {
  filterInstallationsByGithubMembership,
  isEnforceGithubMembership,
} = require("../helpers/githubMembership");
const { resolveTenantLimits } = require("../services/licenseLimits");
const { getSelectionState } = require("../services/repoSelection");

/**
 * Report whether the current tenant has a linked GitHub App installation.
 *
 * Admin and member receive the same result: `hasInstallation` is true only when
 * the tenant has at least one installation in `installation_index` + tenant DB.
 * Members no longer bypass this check (they cannot manage installs, but need a
 * valid org installation to reach the product dashboard).
 *
 * When ENFORCE_GITHUB_MEMBERSHIP=true, only installs the user is a GitHub org
 * member of count (KAN-51).
 *
 * No tenant context → `hasInstallation: false`.
 *
 * `?installationId=<id>` adds `linked`: whether that specific installation is
 * visible to this user yet. The dashboard asks this while it waits for a
 * just-created install to be recorded by the `installation.created` webhook —
 * `hasInstallation` alone cannot tell when an admin is adding a second org.
 */
exports.checkInstallationStatus = async (req, res, next) => {
  try {
    const { login } = req.user || {};

    if (!login) return next(createError(401, "Unauthorized"));

    const requestedId = req.query?.installationId;
    const withLinked = (body, installations) =>
      requestedId == null
        ? body
        : {
            ...body,
            linked: installations.some(
              (installation) => String(installation.installationId) === String(requestedId)
            ),
          };

    if (!req.tenant?.id) {
      return res.status(200).json(withLinked({ hasInstallation: false }, []));
    }

    let installations = await tenantScope.listInstallationsForTenant(req.tenant.id);
    installations = await filterInstallationsByGithubMembership(installations, login);

    return res.status(200).json(
      withLinked(
        {
          hasInstallation: installations.length > 0,
          enforceGithubMembership: isEnforceGithubMembership(),
        },
        installations
      )
    );
  } catch (err) {
    next(
      createError(
        err.response?.status || 500,
        `Failed to check installation status: ${err.message}`
      )
    );
  }
};

exports.listInstallationsForUser = async (req, res, next) => {
  try {
    const { login, role: userRole } = req.user || {};
    if (!login) return next(createError(401, "Unauthorized"));

    if (!req.tenant?.id) {
      return res.json({
        installations: [],
        userRole,
        enforceGithubMembership: isEnforceGithubMembership(),
      });
    }

    let installations = await tenantScope.listInstallationsForTenant(req.tenant.id);
    installations = await filterInstallationsByGithubMembership(installations, login);

    // Carry the repo-selection gate with each installation so the dashboard can
    // show the chooser immediately instead of discovering the block only when a
    // summary start comes back 409. The plan is resolved once for the tenant.
    const limits = await resolveTenantLimits(req.tenant.id).catch(() => null);
    const withSelection = await Promise.all(
      installations.map(async (installation) => ({
        ...installation,
        selection: await getSelectionState(installation, req.tenant.id, {
          limits: limits || undefined,
        }).catch(() => null),
      }))
    );

    res.json({
      installations: withSelection,
      userRole,
      enforceGithubMembership: isEnforceGithubMembership(),
    });
  } catch (err) {
    next(
      createError(
        err.response?.status || 500,
        `Failed to list installations: ${err.message}`
      )
    );
  }
};

/**
 * The installation's repositories, read live from GitHub — limited to the ones
 * Zyloch monitors.
 *
 * This is what the repository dropdowns fall back to before the first sync has
 * stored anything. It used to return everything GitHub lists, so an org with
 * 2,271 repositories on a 2,000-repository plan offered all 2,271 across the app
 * right after the admin had chosen 2,000. An installation still waiting on that
 * choice gets an empty list.
 */
exports.listRepos = async (req, res, next) => {
  try {
    const installation = await tenantScope.assertInstallationBelongsToTenant(
      req.params.installationId,
      req.tenant.id
    );

    const selection = await getSelectionState(installation, req.tenant.id).catch(() => null);
    if (selection?.selectionRequired) return res.json([]);
    const allowlist = new Set(installation?.selectedRepos || []);

    const installationId = Number(req.params.installationId);
    const token = await getInstallationToken(installationId);
    const headers = { Authorization: `Bearer ${token}`, Accept: "application/vnd.github+json" };

    let repos = [];
    let nextUrl = `https://api.github.com/installation/repositories?per_page=100`;

    while (nextUrl) {
      const response = await axios.get(nextUrl, { headers, timeout: 60000 });
      repos = repos.concat(response.data.repositories || []);
      const linkHeader = response.headers.link;
      nextUrl = linkHeader?.match(/<([^>]+)>; rel="next"/)?.[1] || null;
    }

    if (allowlist.size) {
      repos = repos.filter((r) => allowlist.has(String(r.full_name || '').toLowerCase()));
    }

    const formatted = repos.map((r) => ({
      id: r.id,
      full_name: r.full_name,
      private: r.private,
      archived: r.archived || false,
      owner: r.owner.login,
    }));

    res.json(formatted);
  } catch (err) {
    if (err.statusCode) return next(err);
    next(createError(err.response?.status || 500, `Failed to list repositories: ${err.message}`));
  }
};

exports.listBranches = async (req, res, next) => {
  try {
    await tenantScope.assertInstallationBelongsToTenant(req.params.installationId, req.tenant.id);

    const { installationId, owner, repo } = req.params;
    const token = await getInstallationToken(Number(installationId));
    const headers = { Authorization: `Bearer ${token}`, Accept: "application/vnd.github+json" };

    let branches = [];
    let nextUrl = `https://api.github.com/repos/${owner}/${repo}/branches?per_page=100`;

    while (nextUrl) {
      const response = await axios.get(nextUrl, { headers, timeout: 30000 });
      branches = branches.concat(response.data);
      const linkHeader = response.headers.link;
      nextUrl = linkHeader?.match(/<([^>]+)>; rel="next"/)?.[1] || null;
    }

    const normalized = branches.map((b) => ({
      name: b.name,
      protected: b.protected,
    }));

    res.json(normalized);
  } catch (err) {
    if (err.statusCode) return next(err);
    next(createError(err.response?.status || 500, `Failed to list branches: ${err.message}`));
  }
};

exports.listContents = async (req, res, next) => {
  try {
    await tenantScope.assertInstallationBelongsToTenant(req.params.installationId, req.tenant.id);

    const { installationId, owner, repo } = req.params;
    const path = req.query.path || "";
    const token = await getInstallationToken(Number(installationId));
    const headers = { Authorization: `Bearer ${token}`, Accept: "application/vnd.github+json" };

    const urlPath = encodeURIComponent(path).replace(/%2F/g, "/");
    const response = await axios.get(
      `https://api.github.com/repos/${owner}/${repo}/contents/${urlPath}`,
      { headers, timeout: 30000 }
    );

    const items = Array.isArray(response.data) ? response.data : [response.data];
    const normalized = items.map((it) => ({
      type: it.type,
      name: it.name,
      path: it.path,
      sha: it.sha,
      size: it.size,
      download_url: it.download_url,
    }));

    res.json(normalized);
  } catch (err) {
    if (err.statusCode) return next(err);
    next(createError(err.response?.status || 500, `Failed to list contents: ${err.message}`));
  }
};

exports.getFileContent = async (req, res, next) => {
  try {
    await tenantScope.assertInstallationBelongsToTenant(req.params.installationId, req.tenant.id);

    const { installationId, owner, repo } = req.params;
    const path = req.query.path;
    if (!path) return next(createError(400, "Missing path query parameter"));

    const token = await getInstallationToken(Number(installationId));
    const headers = { Authorization: `Bearer ${token}`, Accept: "application/vnd.github+json" };

    const urlPath = encodeURIComponent(path).replace(/%2F/g, "/");
    const response = await axios.get(
      `https://api.github.com/repos/${owner}/${repo}/contents/${urlPath}`,
      { headers, timeout: 30000 }
    );

    res.json({
      name: response.data.name,
      path: response.data.path,
      sha: response.data.sha,
      size: response.data.size,
      encoding: response.data.encoding,
      content: response.data.content,
    });
  } catch (err) {
    if (err.statusCode) return next(err);
    next(createError(err.response?.status || 500, `Failed to fetch file content: ${err.message}`));
  }
};
