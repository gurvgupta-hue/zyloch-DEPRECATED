const path = require('path');
const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');

const TENANT_A = '674a1b2c3d4e5f6789012345';
const INSTALL_ID = 9100;
const ACCOUNT = { id: 42, login: 'acme', type: 'Organization' };
const SENDER = { id: 7, login: 'alice', avatar_url: 'a', html_url: 'h' };

const webhookPath = require.resolve('../controllers/webhook.js');
const authRoutingPath = require.resolve('../services/authRouting.js');
const controlModelsPath = require.resolve('../db/controlModels.js');
const tenantModelsPath = require.resolve('../db/tenantModels.js');
const summaryQueuePath = require.resolve('../queues/summaryQueue.js');
const securityHelperPath = require.resolve('../helpers/securitySignalsHelper.js');
const licenseLimitsPath = require.resolve('../services/licenseLimits.js');
const installationReposPath = require.resolve('../helpers/installationRepos.js');
const tokenHelperPath = require.resolve('../helpers/githubTokenHelper.js');

const stub = (filename, exports) => {
  require.cache[filename] = { id: filename, filename, loaded: true, exports };
};

function fakeRepos(count, prefix = 'acme/repo') {
  return Array.from({ length: count }, (_, i) => ({ full_name: `${prefix}-${i + 1}` }));
}

describe('installation webhooks: repository inventory and plan limits', () => {
  let webhook;
  let platformEvents;
  let installationDocs;
  let storedInstallation;
  let planLimits;
  let apiCalls;
  let apiResult;
  const originals = new Map();

  function preserve(p) {
    originals.set(p, require.cache[p]);
  }

  beforeEach(() => {
    platformEvents = [];
    installationDocs = [];
    storedInstallation = null;
    apiCalls = [];
    planLimits = { tenantId: TENANT_A, active: true, planId: 'basic', maxRepos: 2000, entitlements: {} };
    apiResult = { repositories: [], totalCount: 0, truncated: false };

    [
      webhookPath,
      authRoutingPath,
      controlModelsPath,
      tenantModelsPath,
      summaryQueuePath,
      securityHelperPath,
      licenseLimitsPath,
      installationReposPath,
      tokenHelperPath,
    ].forEach(preserve);

    // Real helpers worth keeping: the cap and the name normaliser are the logic
    // under test, only the network/DB edges are replaced.
    const { capReposToLimit } = require('../services/licenseLimits.js');
    const { toRepoNames } = require('../helpers/installationRepos.js');

    stub(authRoutingPath, {
      getTenantByInstallationId: async () => TENANT_A,
      resolveTenantByIdentity: async () => ({ tenantId: TENANT_A, userId: 'u1' }),
    });

    stub(controlModelsPath, {
      getControlModels: () => ({
        PlatformEvent: {
          create: async (doc) => {
            platformEvents.push(doc);
            return doc;
          },
        },
        InstallationIndex: { updateOne: async () => ({}), deleteOne: async () => ({}) },
      }),
    });

    stub(tenantModelsPath, {
      getTenantModels: (tenantId) => ({
        tenantId: String(tenantId),
        Installation: {
          findOneAndUpdate: async (filter, update) => {
            installationDocs.push(update);
            storedInstallation = { ...storedInstallation, ...update };
            return storedInstallation;
          },
          findOne: async () => storedInstallation,
          find: async () => [],
          deleteMany: async () => ({}),
        },
        User: { findById: () => ({ select: async () => ({ _id: 'u1', role: 'admin', email: 'alice@acme.com' }) }) },
        RepositoryData: { findOneAndUpdate: async () => ({}), deleteOne: async () => ({}) },
        InstallationSummaryJob: {
          findOne: () => ({ sort: async () => null }),
          findOneAndUpdate: async () => ({ _id: 'job-1' }),
          findByIdAndUpdate: async () => ({}),
        },
        Team: {},
        TeamMember: {},
        GitHubSecurityEvent: {},
      }),
    });

    stub(summaryQueuePath, { add: async () => ({ id: 'bull-1' }) });
    stub(securityHelperPath, {
      ingestPatRequestWebhook: async () => ({ inserted: 0 }),
      ingestForkWebhook: async () => ({ inserted: 0 }),
      getSecuritySignalTotals: async () => ({}),
    });
    stub(licenseLimitsPath, {
      capReposToLimit,
      resolveTenantLimits: async () => planLimits,
    });
    stub(installationReposPath, {
      toRepoNames,
      fetchInstallationRepositories: async (token, options) => {
        apiCalls.push({ token, options });
        return apiResult;
      },
    });
    stub(tokenHelperPath, { getInstallationToken: async () => 'ghs_test' });

    delete require.cache[webhookPath];
    webhook = require('../controllers/webhook.js');
  });

  afterEach(() => {
    for (const [p, mod] of originals) {
      if (mod) require.cache[p] = mod;
      else delete require.cache[p];
    }
    originals.clear();
    delete require.cache[webhookPath];
  });

  async function deliver(event, body) {
    let statusCode;
    let responseBody;
    const res = {
      status: (code) => {
        statusCode = code;
        return { json: (data) => { responseBody = data; } };
      },
    };
    await webhook.handleWebhook(
      { headers: { 'x-github-event': event, 'x-github-delivery': 'del-1' }, body },
      res,
      (err) => { if (err) throw err; }
    );
    return { statusCode, responseBody };
  }

  // Over the limit nothing has been chosen yet, so no repository names are kept —
  // only the count that puts the chooser in front of the admin.
  it('stores no repository names for an over-limit install, only the count, and flags the breach', async () => {
    planLimits = { ...planLimits, planId: 'basic', maxRepos: 3 };

    const { statusCode } = await deliver('installation', {
      action: 'created',
      installation: { id: INSTALL_ID, account: ACCOUNT, repository_selection: 'selected' },
      repositories: fakeRepos(5),
      sender: SENDER,
    });

    assert.equal(statusCode, 200);
    const stored = installationDocs[0];
    assert.deepEqual(stored.repos, []);
    assert.equal(stored.repoCount, 5);
    assert.equal(stored.repoLimit, 3);
    assert.equal(stored.reposTruncated, true);
    assert.equal(stored.repositorySelection, 'selected');

    const breach = platformEvents.find((e) => e.eventType === 'installation.repo_limit_exceeded');
    assert.ok(breach, 'expected a repo limit platform event');
    assert.equal(breach.payload.limit, 3);
    assert.equal(breach.payload.totalRepositories, 5);
    assert.equal(breach.payload.storedRepositories, 0);
    assert.equal(breach.tenantId, TENANT_A);
  });

  it('reads the inventory from the API for an all-repositories install, not the payload', async () => {
    // The payload array is the partial snapshot GitHub ships for a big org.
    apiResult = { repositories: fakeRepos(1200), totalCount: 1200, truncated: false };

    await deliver('installation', {
      action: 'created',
      installation: { id: INSTALL_ID, account: ACCOUNT, repository_selection: 'all' },
      repositories: fakeRepos(2),
      sender: SENDER,
    });

    assert.equal(apiCalls.length, 1);
    assert.equal(apiCalls[0].options.limit, 2000, 'API paging must stop at the plan cap');

    const stored = installationDocs[0];
    assert.equal(stored.repos.length, 1200);
    assert.equal(stored.repoCount, 1200);
    assert.equal(stored.reposTruncated, false);
    assert.equal(stored.repositorySelection, 'all');
    assert.equal(platformEvents.length, 0);
  });

  it('enforces the pro cap (5000) on an org larger than the plan allows', async () => {
    planLimits = { ...planLimits, planId: 'pro', maxRepos: 5000 };
    apiResult = { repositories: fakeRepos(5000), totalCount: 6200, truncated: true };

    await deliver('installation', {
      action: 'created',
      installation: { id: INSTALL_ID, account: ACCOUNT, repository_selection: 'all' },
      repositories: [],
      sender: SENDER,
    });

    const stored = installationDocs[0];
    assert.deepEqual(stored.repos, [], 'no names kept before the admin chooses');
    assert.equal(stored.repoCount, 6200);
    assert.equal(stored.repoLimit, 5000);
    assert.equal(stored.reposTruncated, true);
    assert.equal(
      platformEvents.filter((e) => e.eventType === 'installation.repo_limit_exceeded').length,
      1
    );
  });

  it('keeps the installation when the plan is unlimited (maxRepos -1)', async () => {
    planLimits = { ...planLimits, planId: 'enterprise', maxRepos: Number.POSITIVE_INFINITY };
    apiResult = { repositories: fakeRepos(12000), totalCount: 12000, truncated: false };

    await deliver('installation', {
      action: 'created',
      installation: { id: INSTALL_ID, account: ACCOUNT, repository_selection: 'all' },
      repositories: [],
      sender: SENDER,
    });

    const stored = installationDocs[0];
    assert.equal(stored.repos.length, 12000);
    assert.equal(stored.repoLimit, null);
    assert.equal(stored.reposTruncated, false);
    assert.equal(apiCalls[0].options.limit, Number.POSITIVE_INFINITY);
  });

  it('falls back to the payload list when the API call fails', async () => {
    stub(installationReposPath, {
      toRepoNames: require.cache[installationReposPath].exports.toRepoNames,
      fetchInstallationRepositories: async () => {
        throw new Error('bad credentials');
      },
    });
    delete require.cache[webhookPath];
    webhook = require('../controllers/webhook.js');

    await deliver('installation', {
      action: 'created',
      installation: { id: INSTALL_ID, account: ACCOUNT, repository_selection: 'all' },
      repositories: fakeRepos(4),
      sender: SENDER,
    });

    const stored = installationDocs[0];
    assert.equal(stored.repos.length, 4);
    assert.equal(stored.repoCount, 4);
  });

  it('installation_repositories applies additions as well as removals, capped by the plan', async () => {
    storedInstallation = {
      installationId: INSTALL_ID,
      repos: ['acme/a', 'acme/b'],
      repoCount: 2,
      repoLimit: 10,
      repositorySelection: 'selected',
    };

    await deliver('installation_repositories', {
      action: 'added',
      installation: { id: INSTALL_ID, account: ACCOUNT },
      repositories_added: [{ full_name: 'acme/C' }],
      repositories_removed: [{ full_name: 'acme/a' }],
    });

    const update = installationDocs.at(-1);
    assert.deepEqual(update.repos, ['acme/b', 'acme/c']);
    assert.equal(update.repoCount, 2);
    assert.equal(update.reposTruncated, false);
  });

  it('a newly granted repository does not join an existing allowlist on its own', async () => {
    storedInstallation = {
      installationId: INSTALL_ID,
      repos: ['acme/a', 'acme/b'],
      selectedRepos: ['acme/a', 'acme/b'],
      repoCount: 5000,
      repoLimit: 2000,
      repositorySelection: 'all',
    };

    await deliver('installation_repositories', {
      action: 'added',
      installation: { id: INSTALL_ID, account: ACCOUNT },
      repositories_added: [{ full_name: 'acme/brand-new' }],
      repositories_removed: [{ full_name: 'acme/a' }],
    });

    const update = installationDocs.at(-1);
    // The removed repo leaves the allowlist; the new one does not enter it.
    assert.deepEqual(update.repos, ['acme/b']);
    assert.deepEqual(update.selectedRepos, ['acme/b']);
    assert.equal(update.repoCount, 5000, 'still 5000 on GitHub: -1 removed, +1 added');
    assert.equal(update.reposTruncated, true);
  });

  it('installation_repositories pushing an install over the limit keeps no names until a choice is made', async () => {
    planLimits = { ...planLimits, maxRepos: 2 };
    storedInstallation = {
      installationId: INSTALL_ID,
      repos: ['acme/a', 'acme/b'],
      repoCount: 2,
      repoLimit: 2,
      repositorySelection: 'selected',
    };

    await deliver('installation_repositories', {
      action: 'added',
      installation: { id: INSTALL_ID, account: ACCOUNT },
      repositories_added: [{ full_name: 'acme/c' }],
      repositories_removed: [],
    });

    const update = installationDocs.at(-1);
    assert.deepEqual(update.repos, []);
    assert.equal(update.repoCount, 3);
    assert.equal(update.reposTruncated, true);
    assert.ok(platformEvents.some((e) => e.eventType === 'installation.repo_limit_exceeded'));
  });
});
