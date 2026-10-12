const path = require('path');
const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');

const repoCatalog = require('../services/repoCatalog');

const TENANT = '674a1b2c3d4e5f6789012345';
const INSTALL_ID = 4242;

const ghRepo = (fullName, extra = {}) => ({
  id: fullName.length,
  full_name: fullName,
  owner: { login: fullName.split('/')[0] },
  private: false,
  archived: false,
  updated_at: '2026-09-01T00:00:00Z',
  size: 10,
  ...extra,
});

/** A fake GitHub walk: one page per array, reporting progress like the real helper. */
function fakeWalk(pages, { calls = [], gate = null, fail = null } = {}) {
  return async (token, { onPage }) => {
    calls.push(token);
    if (gate) await gate;
    if (fail) throw fail;
    const total = pages.flat().length;
    let read = 0;
    for (const page of pages) {
      read += page.length;
      await onPage(page, { readCount: read, totalCount: total });
    }
    return { readCount: read, totalCount: total, truncated: false };
  };
}

// The chooser's list used to be written to an `installation_repo_catalog`
// collection — every repository the installation could reach, chosen or not.
describe('live repository list for the chooser (never stored)', () => {
  let restore;
  let now;

  beforeEach(() => {
    now = 1_000_000;
    repoCatalog.clearCatalogs();
  });

  afterEach(() => {
    if (restore) restore();
    restore = null;
    repoCatalog.clearCatalogs();
  });

  function use(fetchInstallationRepositories) {
    restore = repoCatalog.setDependencies({
      getInstallationToken: async () => 'ghs_test',
      fetchInstallationRepositories,
      now: () => now,
    });
  }

  it('reads every page into memory and reports progress while it does', async () => {
    let release;
    const gate = new Promise((r) => { release = r; });
    use(fakeWalk([[ghRepo('Acme/One')], [ghRepo('acme/two', { archived: true })]], { gate }));

    const { queued, entry } = repoCatalog.ensureCatalog(INSTALL_ID);
    assert.equal(queued, true);
    assert.equal(repoCatalog.getCatalogStatus(INSTALL_ID).status, 'syncing');
    assert.equal(repoCatalog.getCatalogRepos(INSTALL_ID), null, 'nothing to page until the read finishes');

    release();
    await entry.promise;

    const status = repoCatalog.getCatalogStatus(INSTALL_ID);
    assert.equal(status.status, 'ready');
    assert.equal(status.syncedCount, 2);
    assert.equal(status.totalCount, 2);
    assert.deepEqual(
      repoCatalog.getCatalogRepos(INSTALL_ID).map((r) => [r.fullName, r.isArchived]),
      [['acme/one', false], ['acme/two', true]]
    );
  });

  it('runs one read per installation however often the chooser polls', async () => {
    const calls = [];
    let release;
    const gate = new Promise((r) => { release = r; });
    use(fakeWalk([[ghRepo('acme/one')]], { calls, gate }));

    const first = repoCatalog.ensureCatalog(INSTALL_ID);
    const second = repoCatalog.ensureCatalog(INSTALL_ID);
    assert.equal(second.queued, false);
    assert.equal(second.reason, 'already_syncing');

    release();
    await first.entry.promise;
    assert.equal(repoCatalog.ensureCatalog(INSTALL_ID).queued, false, 'fresh list is reused');
    assert.equal(calls.length, 1);
  });

  it('re-reads after the list goes stale, or when refreshed on purpose', async () => {
    const calls = [];
    use(fakeWalk([[ghRepo('acme/one')]], { calls }));

    await repoCatalog.ensureCatalog(INSTALL_ID).entry.promise;
    await repoCatalog.ensureCatalog(INSTALL_ID, { force: true }).entry.promise;
    assert.equal(calls.length, 2);

    now += repoCatalog.CATALOG_TTL_MS + 1;
    assert.equal(repoCatalog.getCatalogStatus(INSTALL_ID).status, 'idle');
    assert.equal(repoCatalog.getCatalogRepos(INSTALL_ID), null);
    await repoCatalog.ensureCatalog(INSTALL_ID).entry.promise;
    assert.equal(calls.length, 3);
  });

  it('keeps a list that is being used, up to its maximum age', async () => {
    use(fakeWalk([[ghRepo('acme/one')]]));
    await repoCatalog.ensureCatalog(INSTALL_ID).entry.promise;

    // An admin paging through the chooser for longer than the idle window.
    const step = Math.floor(repoCatalog.CATALOG_TTL_MS / 2);
    for (let t = 0; t < 4; t += 1) {
      now += step;
      assert.ok(repoCatalog.getCatalogRepos(INSTALL_ID), 'still held while in use');
    }

    now += repoCatalog.CATALOG_MAX_AGE_MS;
    assert.equal(repoCatalog.getCatalogRepos(INSTALL_ID), null, 're-read once too old');
  });

  it('reports a failed read, and a later visit tries again', async () => {
    use(fakeWalk([], { fail: new Error('GitHub 502') }));
    await repoCatalog.ensureCatalog(INSTALL_ID).entry.promise;

    const status = repoCatalog.getCatalogStatus(INSTALL_ID);
    assert.equal(status.status, 'failed');
    assert.equal(status.error, 'GitHub 502');
    assert.equal(repoCatalog.ensureCatalog(INSTALL_ID).queued, true);
  });
});

describe('repository endpoints never offer or keep unselected repositories', () => {
  const selectionControllerPath = path.resolve(__dirname, '../controllers/repoSelection.js');
  const githubControllerPath = path.resolve(__dirname, '../controllers/github.js');
  const tokenHelperPath = path.resolve(__dirname, '../helpers/githubTokenHelper.js');
  const licenseLimitsPath = path.resolve(__dirname, '../services/licenseLimits.js');
  const repoSelectionPath = path.resolve(__dirname, '../services/repoSelection.js');

  let tenantScope;
  let originalAssert;
  let installation;
  let restore;
  let originalAxiosGet;
  const originals = new Map();

  const stub = (p, exports) => {
    originals.set(p, require.cache[p]);
    require.cache[p] = { id: p, filename: p, loaded: true, exports };
  };

  beforeEach(async () => {
    repoCatalog.clearCatalogs();
    installation = {
      installationId: INSTALL_ID,
      account: { login: 'acme', type: 'Organization' },
      repoCount: 3,
      repos: ['acme/a', 'acme/b'],
      selectedRepos: ['acme/a', 'acme/b'],
      repoSelection: { completedAt: new Date() },
    };
    stub(licenseLimitsPath, {
      resolveTenantLimits: async () => ({ active: true, planId: 'basic', maxRepos: 2 }),
    });
    stub(tokenHelperPath, { getInstallationToken: async () => 'ghs_test' });
    delete require.cache[repoSelectionPath];
    delete require.cache[selectionControllerPath];
    delete require.cache[githubControllerPath];

    tenantScope = require('../helpers/tenantScope');
    originalAssert = tenantScope.assertInstallationBelongsToTenant;
    tenantScope.assertInstallationBelongsToTenant = async () => installation;

    restore = repoCatalog.setDependencies({
      getInstallationToken: async () => 'ghs_test',
      fetchInstallationRepositories: fakeWalk([
        [ghRepo('acme/a'), ghRepo('acme/b'), ghRepo('acme/not-chosen')],
      ]),
    });
  });

  afterEach(() => {
    restore();
    tenantScope.assertInstallationBelongsToTenant = originalAssert;
    for (const [p, mod] of originals) {
      if (mod) require.cache[p] = mod;
      else delete require.cache[p];
    }
    originals.clear();
    delete require.cache[repoSelectionPath];
    delete require.cache[selectionControllerPath];
    delete require.cache[githubControllerPath];
    if (originalAxiosGet) require('axios').get = originalAxiosGet;
    originalAxiosGet = null;
    repoCatalog.clearCatalogs();
  });

  async function call(handler, query = {}) {
    let body;
    let error;
    await handler(
      { params: { installationId: String(INSTALL_ID) }, query, tenant: { id: TENANT }, tenantId: TENANT, models: {} },
      { json: (data) => { body = data; } },
      (err) => { error = err; }
    );
    if (error) throw error;
    return body;
  }

  it('the chooser lists the live repositories with their stored choice, from memory', async () => {
    const controller = require('../controllers/repoSelection');

    const first = await call(controller.listCatalog);
    assert.deepEqual(first.repositories, [], 'nothing until the live read finishes');
    assert.equal(first.catalog.status, 'syncing');

    await repoCatalog.ensureCatalog(INSTALL_ID).entry.promise;

    const all = await call(controller.listCatalog, { sort: 'name' });
    assert.equal(all.total, 3);
    assert.deepEqual(
      all.repositories.map((r) => [r.fullName, r.selected]),
      [['acme/a', true], ['acme/b', true], ['acme/not-chosen', false]]
    );

    const unselected = await call(controller.listCatalog, { filter: 'unselected' });
    assert.deepEqual(unselected.repositories.map((r) => r.fullName), ['acme/not-chosen']);

    const searched = await call(controller.listCatalog, { q: 'NOT-ch' });
    assert.equal(searched.total, 1);
  });

  it('the live repository list only returns the selected repositories', async () => {
    const axios = require('axios');
    originalAxiosGet = axios.get;
    axios.get = async () => ({
      data: { repositories: [ghRepo('Acme/A'), ghRepo('acme/b'), ghRepo('acme/not-chosen')] },
      headers: {},
    });
    const github = require('../controllers/github');

    const repos = await call(github.listRepos);

    assert.deepEqual(repos.map((r) => r.full_name), ['Acme/A', 'acme/b']);
  });

  it('the live repository list is empty while a choice is still required', async () => {
    installation = { ...installation, selectedRepos: [], repoSelection: { completedAt: null } };
    const axios = require('axios');
    originalAxiosGet = axios.get;
    let called = false;
    axios.get = async () => { called = true; return { data: { repositories: [] }, headers: {} }; };
    const github = require('../controllers/github');

    assert.deepEqual(await call(github.listRepos), []);
    assert.equal(called, false, 'GitHub is not even asked');
  });
});
