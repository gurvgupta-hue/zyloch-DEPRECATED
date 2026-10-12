const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');

const TENANT = '674a1b2c3d4e5f6789012345';
const INSTALL_ID = 4242;

const licenseLimitsPath = require.resolve('../services/licenseLimits.js');
const repoSelectionPath = require.resolve('../services/repoSelection.js');
const repoCatalog = require('../services/repoCatalog');

/** Hold `rows` as the installation's live GitHub list, as the chooser would. */
async function holdLiveList(rows) {
  const restore = repoCatalog.setDependencies({
    getInstallationToken: async () => 'ghs_test',
    fetchInstallationRepositories: async (token, { onPage }) => {
      const page = rows.map((row) => ({
        full_name: row.fullName,
        archived: !!row.isArchived,
        updated_at: row.repoUpdatedAt || null,
      }));
      await onPage(page, { readCount: page.length, totalCount: page.length });
      return { readCount: page.length, totalCount: page.length, truncated: false };
    },
  });
  try {
    await repoCatalog.ensureCatalog(INSTALL_ID, { force: true }).entry.promise;
  } finally {
    restore();
  }
}

describe('repo selection gate (over-limit installations)', () => {
  let repoSelection;
  let limits;
  let originalLicenseLimits;
  let installationDoc;

  const installation = (overrides = {}) => ({
    installationId: INSTALL_ID,
    account: { login: 'acme', type: 'Organization' },
    repos: [],
    repoCount: 0,
    selectedRepos: [],
    repoSelection: { completedAt: null },
    ...overrides,
  });

  const models = () => ({
    Installation: {
      findOneAndUpdate: async (filter, update) => {
        installationDoc = { ...installationDoc, ...(update.$set || update) };
        // Mirror the dotted paths the service writes.
        const set = update.$set || {};
        installationDoc.repoSelection = {
          ...installationDoc.repoSelection,
          ...(set['repoSelection.completedAt'] !== undefined
            ? { completedAt: set['repoSelection.completedAt'] }
            : {}),
          ...(set['repoSelection.source'] !== undefined
            ? { source: set['repoSelection.source'] }
            : {}),
        };
        return installationDoc;
      },
    },
  });

  beforeEach(() => {
    limits = { tenantId: TENANT, active: true, planId: 'basic', maxRepos: 2000, entitlements: {} };
    installationDoc = installation();
    repoCatalog.clearCatalogs();

    originalLicenseLimits = require.cache[licenseLimitsPath];
    require.cache[licenseLimitsPath] = {
      id: licenseLimitsPath,
      filename: licenseLimitsPath,
      loaded: true,
      exports: { resolveTenantLimits: async () => limits },
    };

    delete require.cache[repoSelectionPath];
    repoSelection = require('../services/repoSelection.js');
  });

  afterEach(() => {
    repoCatalog.clearCatalogs();
    if (originalLicenseLimits) require.cache[licenseLimitsPath] = originalLicenseLimits;
    else delete require.cache[licenseLimitsPath];
    delete require.cache[repoSelectionPath];
  });

  it('blocks an installation with more repositories than the plan covers', async () => {
    const state = await repoSelection.getSelectionState(
      installation({ repoCount: 21430 }),
      TENANT
    );

    assert.equal(state.selectionRequired, true);
    assert.equal(state.limit, 2000);
    assert.equal(state.overBy, 19430);
    assert.equal(state.planId, 'basic');
  });

  it('does not block when the installation fits the plan', async () => {
    const state = await repoSelection.getSelectionState(installation({ repoCount: 120 }), TENANT);
    assert.equal(state.selectionRequired, false);
    assert.equal(state.overBy, 0);
  });

  it('never blocks an unlimited plan', async () => {
    limits = { ...limits, planId: 'enterprise', maxRepos: Number.POSITIVE_INFINITY };
    const state = await repoSelection.getSelectionState(
      installation({ repoCount: 99999 }),
      TENANT
    );
    assert.equal(state.selectionRequired, false);
    assert.equal(state.unlimited, true);
    assert.equal(state.limit, null);
  });

  it('stays blocked until a recorded selection fits the current plan', async () => {
    const chosen = Array.from({ length: 2000 }, (_, i) => `acme/repo-${i}`);

    const after = await repoSelection.getSelectionState(
      installation({
        repoCount: 21430,
        selectedRepos: chosen,
        repoSelection: { completedAt: new Date() },
      }),
      TENANT
    );
    assert.equal(after.selectionRequired, false);
    assert.equal(after.selectedCount, 2000);

    // Downgrade: the same recorded choice no longer fits, so the gate returns.
    limits = { ...limits, planId: 'basic', maxRepos: 1000 };
    const downgraded = await repoSelection.getSelectionState(
      installation({
        repoCount: 21430,
        selectedRepos: chosen,
        repoSelection: { completedAt: new Date() },
      }),
      TENANT
    );
    assert.equal(downgraded.selectionRequired, true);
  });

  it('rejects a selection larger than the plan limit', async () => {
    limits = { ...limits, maxRepos: 2 };
    await assert.rejects(
      () =>
        repoSelection.saveSelection(models(), {
          tenantId: TENANT,
          installation: installation({ repoCount: 10 }),
          repos: ['acme/a', 'acme/b', 'acme/c'],
        }),
      (err) =>
        err.statusCode === 403 &&
        err.code === 'LICENSE_LIMIT_EXCEEDED' &&
        err.limit === 2 &&
        err.current === 3
    );
  });

  it('normalizes, dedupes and validates repository names', () => {
    assert.deepEqual(
      repoSelection.normalizeRepoNames(['Acme/Repo-One', 'acme/repo-one', 'ACME/Two']),
      ['acme/repo-one', 'acme/two']
    );
    assert.throws(() => repoSelection.normalizeRepoNames('nope'), /must be an array/);
    assert.throws(() => repoSelection.normalizeRepoNames(['no-slash']), /Invalid repository name/);
    assert.throws(() => repoSelection.normalizeRepoNames([{}]), /only "owner\/name" strings/);
  });

  it('saves a fitting selection and clears the gate', async () => {
    await holdLiveList([
      { fullName: 'acme/a', isArchived: false, repoUpdatedAt: '2026-09-01' },
      { fullName: 'acme/b', isArchived: false, repoUpdatedAt: '2026-08-01' },
      { fullName: 'acme/c', isArchived: false, repoUpdatedAt: '2026-07-01' },
    ]);
    limits = { ...limits, maxRepos: 2 };
    installationDoc = installation({ repoCount: 10 });

    const state = await repoSelection.saveSelection(models(), {
      tenantId: TENANT,
      installation: installationDoc,
      repos: ['acme/a', 'acme/b'],
      actorEmail: 'admin@acme.com',
    });

    assert.deepEqual(installationDoc.selectedRepos, ['acme/a', 'acme/b']);
    // The rest of the app reads `repos` as "this installation's repositories".
    assert.deepEqual(installationDoc.repos, ['acme/a', 'acme/b']);
    assert.equal(installationDoc.reposTruncated, true, '10 repos, 2 monitored');
    assert.equal(state.selectionRequired, false);
    assert.equal(state.selectedCount, 2);
  });

  it('writes only the chosen repositories — nothing about the ones left out', async () => {
    await holdLiveList([
      { fullName: 'acme/a' },
      { fullName: 'acme/b' },
      { fullName: 'acme/not-chosen' },
    ]);
    limits = { ...limits, maxRepos: 2 };
    const writes = [];
    const recording = {
      Installation: {
        findOneAndUpdate: async (filter, update) => {
          writes.push(update);
          return models().Installation.findOneAndUpdate(filter, update);
        },
      },
    };

    await repoSelection.saveSelection(recording, {
      tenantId: TENANT,
      installation: installation({ repoCount: 3 }),
      repos: ['acme/a', 'acme/b'],
    });

    assert.equal(writes.length, 1, 'one write, to the installation');
    assert.ok(!JSON.stringify(writes).includes('not-chosen'));
  });

  it('refuses repositories the installation cannot reach while the live list is held', async () => {
    await holdLiveList([{ fullName: 'acme/a' }]);
    await assert.rejects(
      () =>
        repoSelection.saveSelection(models(), {
          tenantId: TENANT,
          installation: installation({ repoCount: 10 }),
          repos: ['acme/a', 'acme/ghost'],
        }),
      /not accessible to this installation/
    );
  });

  it('auto-selects the most recently active repositories that fit', async () => {
    limits = { ...limits, maxRepos: 2 };
    await holdLiveList([
      { fullName: 'acme/stale', isArchived: false, repoUpdatedAt: '2021-01-01' },
      { fullName: 'acme/hot', isArchived: false, repoUpdatedAt: '2026-09-10' },
      { fullName: 'acme/warm', isArchived: false, repoUpdatedAt: '2026-08-10' },
      { fullName: 'acme/archived', isArchived: true, repoUpdatedAt: '2026-09-15' },
    ]);
    installationDoc = installation({ repoCount: 4 });

    const state = await repoSelection.autoSelect(models(), {
      tenantId: TENANT,
      installation: installationDoc,
    });

    assert.deepEqual(installationDoc.selectedRepos, ['acme/hot', 'acme/warm']);
    assert.equal(installationDoc.repoSelection.source, 'auto');
    assert.equal(state.selectionRequired, false);
  });

  it('will not auto-select before the live list has been read', async () => {
    const restore = repoCatalog.setDependencies({
      getInstallationToken: () => new Promise(() => {}), // still reading
    });
    try {
      await assert.rejects(
        () => repoSelection.autoSelect(models(), { tenantId: TENANT, installation: installation() }),
        (err) => err.statusCode === 409
      );
      assert.equal(repoCatalog.getCatalogStatus(INSTALL_ID).status, 'syncing', 'a read was started');
    } finally {
      restore();
    }
  });

  it('reports the live read as the gate\'s catalog status', async () => {
    assert.equal((await repoSelection.getSelectionState(installation(), TENANT)).catalog.status, 'idle');
    await holdLiveList([{ fullName: 'acme/a' }, { fullName: 'acme/b' }]);
    const { catalog } = await repoSelection.getSelectionState(installation(), TENANT);
    assert.equal(catalog.status, 'ready');
    assert.equal(catalog.totalCount, 2);
  });
});
