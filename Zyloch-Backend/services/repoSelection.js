/**
 * Repository selection for installations that exceed their plan's repo limit.
 *
 * An org can install the App on "All repositories" and hand us 21,000 repos on a
 * plan that covers 2,000. Silently ingesting the first 2,000 would leave the
 * admin with a dashboard that looks complete and is not, so the installation is
 * held until someone says which repositories Zyloch should monitor.
 *
 * The limit itself always comes from `license_plans.maxRepos` (Basic 2000 /
 * Pro 5000 today) via services/licenseLimits.js — never a constant here — and a
 * negative limit means unlimited, in which case nothing is ever blocked.
 *
 * Only the chosen repositories are ever stored. The list the admin chooses from
 * is read live from GitHub and held in memory (services/repoCatalog.js).
 */

const createError = require('../utils/createError');
const { resolveTenantLimits } = require('./licenseLimits');
const repoCatalog = require('./repoCatalog');

/** Normalize a client-supplied repository list to catalog keys. */
function normalizeRepoNames(repos) {
  if (!Array.isArray(repos)) {
    throw createError(400, 'repos must be an array of "owner/name" strings');
  }

  const seen = new Set();
  for (const entry of repos) {
    if (typeof entry !== 'string') {
      throw createError(400, 'repos must contain only "owner/name" strings');
    }
    const name = entry.trim().toLowerCase();
    if (!/^[^/\s]+\/[^/\s]+$/.test(name)) {
      throw createError(400, `Invalid repository name: ${entry}`);
    }
    seen.add(name);
  }
  return [...seen];
}

/**
 * The gate state for one installation.
 *
 * `selectionRequired` is the single flag the UI blocks on. It stays true across
 * page loads and logins until a selection that fits the *current* plan is
 * recorded, which is what makes the block survive a user navigating away — the
 * answer is stored on the installation, not in the session.
 */
async function getSelectionState(installation, tenantId, { limits } = {}) {
  const resolved = limits || (await resolveTenantLimits(tenantId));
  const limit = resolved.maxRepos;
  const unlimited = !Number.isFinite(limit);

  const selected = installation.selectedRepos || [];
  const repoCount = Math.max(
    Number(installation.repoCount) || 0,
    (installation.repos || []).length
  );

  const hasValidSelection =
    !!installation.repoSelection?.completedAt &&
    selected.length > 0 &&
    (unlimited || selected.length <= limit);

  const overLimit = !unlimited && repoCount > limit;

  return {
    installationId: installation.installationId,
    accountLogin: installation.account?.login || null,
    accountType: installation.account?.type || null,
    planId: resolved.planId,
    licenseActive: !!resolved.active,
    limit: unlimited ? null : limit,
    unlimited,
    repoCount,
    repositorySelection: installation.repositorySelection || 'selected',
    selectedCount: selected.length,
    overBy: overLimit ? repoCount - limit : 0,
    selectionRequired: overLimit && !hasValidSelection,
    selectionCompletedAt: installation.repoSelection?.completedAt || null,
    selectionSource: installation.repoSelection?.source || null,
    catalog: repoCatalog.getCatalogStatus(installation.installationId),
  };
}

/**
 * Record the repositories an installation will monitor.
 *
 * Rejects a selection larger than the plan allows — that is the whole point of
 * the gate — and, while the live list is held, rejects names the installation
 * cannot actually reach. Only these names are written; nothing about the
 * repositories left out is kept.
 */
async function saveSelection(
  models,
  { tenantId, installation, repos, actorEmail = null, source = 'manual' }
) {
  const { Installation } = models;
  const limits = await resolveTenantLimits(tenantId);
  const limit = limits.maxRepos;
  const names = normalizeRepoNames(repos);

  if (names.length === 0) {
    throw createError(400, 'Select at least one repository to monitor');
  }

  if (Number.isFinite(limit) && names.length > limit) {
    const err = createError(
      403,
      `Your ${limits.planId || 'current'} plan covers ${limit} repositories. ` +
        `Remove ${names.length - limit} to continue, or upgrade your plan.`
    );
    err.code = 'LICENSE_LIMIT_EXCEEDED';
    err.limitKey = 'maxRepos';
    err.limit = limit;
    err.current = names.length;
    throw err;
  }

  const installationId = installation.installationId;
  const reachable = repoCatalog.getCatalogRepos(installationId);
  if (reachable) {
    const known = new Set(reachable.map((repo) => repo.fullName));
    if (!names.every((name) => known.has(name))) {
      throw createError(
        400,
        'Some selected repositories are not accessible to this installation. ' +
          'Refresh the repository list and try again.'
      );
    }
  }

  const repoCount = Math.max(
    Number(installation.repoCount) || 0,
    (installation.repos || []).length,
    names.length
  );

  const updated = await Installation.findOneAndUpdate(
    { installationId },
    {
      $set: {
        selectedRepos: names,
        // `repos` is what the rest of the app reads as "this installation's
        // repositories", so the choice has to land there too or the dashboard
        // would keep counting repositories nobody asked us to monitor.
        repos: names,
        repoCount,
        repoLimit: Number.isFinite(limit) ? limit : null,
        reposTruncated: repoCount > names.length,
        'repoSelection.completedAt': new Date(),
        'repoSelection.completedBy': actorEmail,
        'repoSelection.source': source,
        'repoSelection.limitAtSelection': Number.isFinite(limit) ? limit : null,
      },
    },
    { new: true }
  );

  return getSelectionState(updated, tenantId, { limits });
}

/**
 * Pick the most recently active repositories that fit the plan.
 *
 * Active repositories first, archived last: an archived repo is the one an admin
 * is least likely to want a scan seat spent on.
 */
async function autoSelect(models, { tenantId, installation, actorEmail = null }) {
  const limits = await resolveTenantLimits(tenantId);
  const limit = limits.maxRepos;

  if (!Number.isFinite(limit) || limit <= 0) {
    throw createError(
      400,
      'Automatic selection needs a plan with a repository limit; nothing to trim to'
    );
  }

  const reachable = repoCatalog.getCatalogRepos(installation.installationId);
  if (!reachable) {
    repoCatalog.ensureCatalog(installation.installationId);
    throw createError(409, 'The repository list is still being built. Try again in a moment.');
  }

  const chosen = sortCatalog(reachable, 'active').slice(0, limit);

  return saveSelection(models, {
    tenantId,
    installation,
    repos: chosen.map((repo) => repo.fullName),
    actorEmail,
    source: 'auto',
  });
}

const timeOf = (value) => (value ? new Date(value).getTime() || 0 : 0);

const CATALOG_SORTS = Object.freeze({
  // Most recently active first, archived repositories last — the order an admin
  // trimming a list actually wants.
  active: (a, b) =>
    Number(a.isArchived) - Number(b.isArchived) ||
    timeOf(b.updatedAt) - timeOf(a.updatedAt) ||
    a.fullName.localeCompare(b.fullName),
  name: (a, b) => a.fullName.localeCompare(b.fullName),
  size: (a, b) => b.sizeKb - a.sizeKb || a.fullName.localeCompare(b.fullName),
});

/** A sorted copy of the live list. Unknown sort keys fall back to `active`. */
function sortCatalog(repos, sort) {
  return [...repos].sort(CATALOG_SORTS[sort] || CATALOG_SORTS.active);
}

module.exports = {
  CATALOG_SORTS,
  normalizeRepoNames,
  getSelectionState,
  saveSelection,
  autoSelect,
  sortCatalog,
};
