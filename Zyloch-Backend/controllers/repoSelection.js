/**
 * The repository chooser an installation must pass through when it holds more
 * repositories than its plan covers (see services/repoSelection.js for the
 * rules, and services/repoCatalog.js for the list it pages through — read live
 * from GitHub and held in memory, never stored).
 */

const createError = require('../utils/createError');
const tenantScope = require('../helpers/tenantScope');
const { validatePositiveInteger } = require('../utils/validation');
const {
  getSelectionState,
  saveSelection,
  autoSelect,
  sortCatalog,
} = require('../services/repoSelection');
const repoCatalog = require('../services/repoCatalog');

const MAX_PAGE_SIZE = 100;

async function loadInstallation(req) {
  const installationId = validatePositiveInteger(req.params.installationId, 'installationId');
  const installation = await tenantScope.assertInstallationBelongsToTenant(
    installationId,
    req.tenant.id
  );
  return { installationId, installation };
}

/**
 * Gate state for one installation, and a live read of its repository list
 * kicked off when the chooser is going to need it. The UI polls this while the
 * list is read.
 */
async function getState(req, res, next) {
  try {
    const { installation } = await loadInstallation(req);
    const state = await getSelectionState(installation, req.tenantId);

    if (state.selectionRequired) {
      repoCatalog.ensureCatalog(installation.installationId);
      state.catalog = repoCatalog.getCatalogStatus(installation.installationId);
    }

    res.json(state);
  } catch (err) {
    if (err.statusCode) return next(err);
    next(createError(500, `Failed to read repository selection: ${err.message}`));
  }
}

/** Re-read the list from GitHub (the chooser's "refresh list" action). */
async function syncCatalog(req, res, next) {
  try {
    const { installation } = await loadInstallation(req);
    const result = repoCatalog.ensureCatalog(installation.installationId, { force: true });
    const state = await getSelectionState(installation, req.tenantId);
    res.json({ ...state, queued: result.queued });
  } catch (err) {
    if (err.statusCode) return next(err);
    next(createError(500, `Failed to refresh the repository list: ${err.message}`));
  }
}

/**
 * One page of the live list: searched, sorted and filtered in memory.
 *
 * Paging server-side is not an optimisation here — the browser cannot hold, sort
 * or filter 21,000 rows responsively, and GitHub's API can neither search nor
 * sort an installation's repository list. `selected` comes from the choice
 * stored on the installation; nothing about the other repositories is stored.
 */
async function listCatalog(req, res, next) {
  try {
    const { installationId, installation } = await loadInstallation(req);

    const page = Math.max(Number(req.query.page) || 1, 1);
    const perPage = Math.min(Math.max(Number(req.query.perPage) || 50, 1), MAX_PAGE_SIZE);
    const catalog = repoCatalog.getCatalogStatus(installationId);
    const selected = new Set(installation.selectedRepos || []);

    let repos = repoCatalog.getCatalogRepos(installationId);
    if (!repos) {
      // Expired or never read: start a read and let the chooser poll for it.
      repoCatalog.ensureCatalog(installationId);
      return res.json({
        repositories: [],
        page,
        perPage,
        total: 0,
        totalPages: 1,
        selectedCount: selected.size,
        catalog: repoCatalog.getCatalogStatus(installationId),
      });
    }

    const term = String(req.query.q || '').trim().toLowerCase();
    if (term) repos = repos.filter((repo) => repo.fullName.includes(term));
    if (req.query.filter === 'selected') repos = repos.filter((repo) => selected.has(repo.fullName));
    if (req.query.filter === 'unselected') repos = repos.filter((repo) => !selected.has(repo.fullName));

    const total = repos.length;
    const rows = sortCatalog(repos, req.query.sort).slice((page - 1) * perPage, page * perPage);

    res.json({
      repositories: rows.map((repo) => ({ ...repo, selected: selected.has(repo.fullName) })),
      page,
      perPage,
      total,
      totalPages: Math.max(Math.ceil(total / perPage), 1),
      selectedCount: selected.size,
      catalog,
    });
  } catch (err) {
    if (err.statusCode) return next(err);
    next(createError(500, `Failed to list repositories: ${err.message}`));
  }
}

/** Record the chosen repositories. */
async function saveState(req, res, next) {
  try {
    const { installation } = await loadInstallation(req);
    const state = await saveSelection(req.models, {
      tenantId: req.tenantId,
      installation,
      repos: req.body?.repos,
      actorEmail: req.user?.email || null,
    });
    res.json(state);
  } catch (err) {
    if (err.statusCode) return next(err);
    next(createError(500, `Failed to save the repository selection: ${err.message}`));
  }
}

/** Fill the selection with the most recently active repositories that fit. */
async function autoSelectState(req, res, next) {
  try {
    const { installation } = await loadInstallation(req);
    const state = await autoSelect(req.models, {
      tenantId: req.tenantId,
      installation,
      actorEmail: req.user?.email || null,
    });
    res.json(state);
  } catch (err) {
    if (err.statusCode) return next(err);
    next(createError(500, `Failed to auto-select repositories: ${err.message}`));
  }
}

module.exports = { getState, syncCatalog, listCatalog, saveState, autoSelectState };
