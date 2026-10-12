/**
 * The list of repositories an installation can reach, read live from GitHub for
 * the repository chooser — and never written to the database.
 *
 * Only the repositories a customer *chooses* are stored (on the installation, and
 * then as scanned `RepositoryData`). The full list, and its metadata, used to be
 * persisted in an `installation_repo_catalog` collection; for an org of 2,271
 * repositories on a 2,000-repository plan that kept 271 repositories nobody
 * selected in the tenant database indefinitely.
 *
 * Instead the list is walked from `GET /installation/repositories` when the
 * chooser needs it and held in this process for a short while, so searching,
 * sorting and paging stay instant without re-walking GitHub per keystroke. A
 * large org takes a while to walk, so the walk runs in the background and its
 * progress is reported the way the stored catalog's was.
 *
 * The cache is per process. With several backend replicas each builds its own
 * copy on first use — more GitHub calls, same result.
 */

const { fetchInstallationRepositories } = require('../helpers/installationRepos');

/**
 * A list unused for this long is dropped. Counted from the last use, so an admin
 * working through a large org is never left with a list that vanished mid-choice.
 */
const CATALOG_TTL_MS = Number(process.env.REPO_CATALOG_TTL_MS || 10 * 60 * 1000);
/** However much it is used, a list older than this is read again from GitHub. */
const CATALOG_MAX_AGE_MS = Number(process.env.REPO_CATALOG_MAX_AGE_MS || 60 * 60 * 1000);
/** Installations kept at once; the least recently used is dropped past this. */
const MAX_CACHED_INSTALLATIONS = Number(process.env.REPO_CATALOG_MAX_CACHED || 50);
/** A ceiling on one walk, so a pathological account cannot page forever. */
const MAX_CATALOG_REPOS = Number(process.env.REPO_CATALOG_MAX || 50000);
const PAGE_SIZE = 100;

const entries = new Map();

let deps = {
  // Required lazily: config/github.js exits the process at import when the
  // GitHub App env vars are absent.
  getInstallationToken: (installationId) =>
    require('../helpers/githubTokenHelper').getInstallationToken(installationId),
  fetchInstallationRepositories,
  now: () => Date.now(),
};

/** Test seam. Returns a function restoring the real dependencies. */
function setDependencies(overrides) {
  const previous = deps;
  deps = { ...deps, ...overrides };
  return () => {
    deps = previous;
  };
}

function toCatalogRepo(repo) {
  const fullName = String(repo.full_name || '').toLowerCase();
  const [owner, name] = fullName.split('/');
  return {
    fullName,
    owner: owner || String(repo.owner?.login || '').toLowerCase(),
    name: name || String(repo.name || '').toLowerCase(),
    isPrivate: !!repo.private,
    isArchived: !!repo.archived,
    isFork: !!repo.fork,
    updatedAt: repo.updated_at || null,
    pushedAt: repo.pushed_at || null,
    sizeKb: Number(repo.size) || 0,
  };
}

function isExpired(entry) {
  if (entry.status !== 'ready') return false;
  const now = deps.now();
  return now - entry.lastUsedAt > CATALOG_TTL_MS || now - entry.readyAt > CATALOG_MAX_AGE_MS;
}

function touch(key, entry) {
  // Map keeps insertion order; re-inserting marks it most recently used.
  entries.delete(key);
  entries.set(key, entry);
  while (entries.size > MAX_CACHED_INSTALLATIONS) {
    const oldestKey = entries.keys().next().value;
    if (entries.get(oldestKey)?.status === 'syncing') break; // never drop a walk mid-flight
    entries.delete(oldestKey);
  }
}

function walk(key, installationId) {
  const entry = {
    status: 'syncing',
    repos: [],
    readCount: 0,
    totalCount: 0,
    error: null,
    readyAt: null,
    lastUsedAt: null,
    promise: null,
  };

  entry.promise = (async () => {
    try {
      const token = await deps.getInstallationToken(installationId);
      const collected = [];
      const result = await deps.fetchInstallationRepositories(token, {
        limit: MAX_CATALOG_REPOS,
        perPage: PAGE_SIZE,
        collect: false,
        onPage: async (page, progress) => {
          for (const repo of page) collected.push(toCatalogRepo(repo));
          entry.readCount = progress.readCount;
          entry.totalCount = progress.totalCount;
        },
      });

      if (result.truncated) {
        console.warn(
          `[RepoCatalog] Installation ${installationId} has ${result.totalCount} repositories; ` +
            `the chooser list stops at the ${MAX_CATALOG_REPOS} safety ceiling`
        );
      }

      entry.repos = collected;
      entry.readCount = result.readCount;
      entry.totalCount = Math.max(result.totalCount, result.readCount);
      entry.status = 'ready';
      entry.readyAt = deps.now();
      entry.lastUsedAt = entry.readyAt;
    } catch (error) {
      entry.status = 'failed';
      entry.error = error.message;
      console.error(`[RepoCatalog] Could not list repositories for installation ${installationId}: ${error.message}`);
    }
    return entry;
  })();

  touch(key, entry);
  return entry;
}

/**
 * Start reading the list unless a fresh one is held or a read is under way.
 * Returns immediately; poll `getCatalogStatus` (or await `entry.promise`).
 */
function ensureCatalog(installationId, { force = false } = {}) {
  const key = String(installationId);
  const entry = entries.get(key);

  if (entry?.status === 'syncing') return { queued: false, reason: 'already_syncing', entry };
  if (entry && !force && entry.status === 'ready' && !isExpired(entry)) {
    return { queued: false, entry };
  }
  return { queued: true, entry: walk(key, installationId) };
}

/** The shape the chooser has always polled: status plus read progress. */
function getCatalogStatus(installationId) {
  const entry = entries.get(String(installationId));
  if (!entry || isExpired(entry)) {
    return { status: 'idle', syncedCount: 0, totalCount: 0, lastSyncedAt: null, error: null };
  }
  return {
    status: entry.status,
    syncedCount: entry.readCount,
    totalCount: entry.totalCount,
    lastSyncedAt: entry.readyAt ? new Date(entry.readyAt) : null,
    error: entry.error,
  };
}

/** The walked list, or null until a read has finished. */
function getCatalogRepos(installationId) {
  const key = String(installationId);
  const entry = entries.get(key);
  if (!entry || entry.status !== 'ready' || isExpired(entry)) return null;
  entry.lastUsedAt = deps.now();
  touch(key, entry);
  return entry.repos;
}

function forgetCatalog(installationId) {
  entries.delete(String(installationId));
}

function clearCatalogs() {
  entries.clear();
}

module.exports = {
  CATALOG_TTL_MS,
  CATALOG_MAX_AGE_MS,
  MAX_CATALOG_REPOS,
  ensureCatalog,
  getCatalogStatus,
  getCatalogRepos,
  forgetCatalog,
  clearCatalogs,
  setDependencies,
};
