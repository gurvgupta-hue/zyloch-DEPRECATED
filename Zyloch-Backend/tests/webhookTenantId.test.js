const path = require('path');
const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');

const TENANT_A = '674a1b2c3d4e5f6789012345';
const INSTALL_ID = 9001;

const webhookPath = path.resolve(__dirname, '../controllers/webhook.js');
const authRoutingPath = path.resolve(__dirname, '../services/authRouting.js');
const controlModelsPath = path.resolve(__dirname, '../db/controlModels.js');
const tenantModelsPath = path.resolve(__dirname, '../db/tenantModels.js');
const summaryQueuePath = path.resolve(__dirname, '../queues/summaryQueue.js');
const securityHelperPath = path.resolve(__dirname, '../helpers/securitySignalsHelper.js');

describe('KAN-39 webhook tenantId + unlinked handling', () => {
  let webhook;
  let platformEvents;
  let originalAuthRouting;
  let originalControlModels;
  let originalTenantModels;
  let originalSecurityHelper;

  beforeEach(() => {
    platformEvents = [];

    originalAuthRouting = require.cache[authRoutingPath];
    originalControlModels = require.cache[controlModelsPath];
    originalTenantModels = require.cache[tenantModelsPath];
    originalSecurityHelper = require.cache[securityHelperPath];

    require.cache[authRoutingPath] = {
      id: authRoutingPath,
      filename: authRoutingPath,
      loaded: true,
      exports: {
        getTenantByInstallationId: async () => null,
        resolveTenantByIdentity: async () => null,
      },
    };

    require.cache[controlModelsPath] = {
      id: controlModelsPath,
      filename: controlModelsPath,
      loaded: true,
      exports: {
        getControlModels: () => ({
          PlatformEvent: {
            create: async (doc) => {
              platformEvents.push(doc);
              return doc;
            },
          },
          InstallationIndex: {
            updateOne: async () => ({}),
            deleteOne: async () => ({}),
          },
        }),
      },
    };

    require.cache[tenantModelsPath] = {
      id: tenantModelsPath,
      filename: tenantModelsPath,
      loaded: true,
      exports: {
        getTenantModels: (tenantId) => ({
          tenantId: String(tenantId),
          Installation: {
            findOneAndUpdate: async () => ({}),
            find: async () => [],
            deleteMany: async () => ({}),
            findOne: async () => null,
          },
          User: {
            findById: () => ({
              select: async () => null,
            }),
          },
          Team: {
            findOneAndUpdate: async () => ({}),
            findOne: async () => null,
            deleteOne: async () => ({}),
          },
          TeamMember: {
            findOneAndUpdate: async () => ({}),
            deleteMany: async () => ({}),
            deleteOne: async () => ({}),
            countDocuments: async () => 0,
          },
          RepositoryData: {
            findOneAndUpdate: async () => ({}),
            deleteOne: async () => ({}),
          },
          InstallationSummaryJob: {
            findOne: () => ({ sort: async () => null }),
            findOneAndUpdate: async () => ({ _id: 'job-1' }),
            findByIdAndUpdate: async () => ({}),
          },
          GitHubSecurityEvent: {},
        }),
      },
    };

    require.cache[summaryQueuePath] = {
      id: summaryQueuePath,
      filename: summaryQueuePath,
      loaded: true,
      exports: {
        add: async () => ({ id: 'bull-1' }),
      },
    };

    require.cache[securityHelperPath] = {
      id: securityHelperPath,
      filename: securityHelperPath,
      loaded: true,
      exports: {
        ingestPatRequestWebhook: async () => ({ inserted: 0 }),
        ingestForkWebhook: async () => ({ inserted: 0 }),
        getSecuritySignalTotals: async () => ({
          totalSecurityEvents: 0,
          totalPatNoExpiry: 0,
          totalPatExpired: 0,
          totalPatOverPermissive: 0,
          totalExternalForks: 0,
        }),
      },
    };

    delete require.cache[webhookPath];
    webhook = require('../controllers/webhook');
  });

  afterEach(() => {
    if (originalAuthRouting) require.cache[authRoutingPath] = originalAuthRouting;
    else delete require.cache[authRoutingPath];
    if (originalControlModels) require.cache[controlModelsPath] = originalControlModels;
    else delete require.cache[controlModelsPath];
    if (originalTenantModels) require.cache[tenantModelsPath] = originalTenantModels;
    else delete require.cache[tenantModelsPath];
    if (originalSecurityHelper) require.cache[securityHelperPath] = originalSecurityHelper;
    else delete require.cache[securityHelperPath];
    delete require.cache[summaryQueuePath];
    delete require.cache[webhookPath];
  });

  it('handleUnlinkedInstallation logs queue event for admin link', async () => {
    const body = await webhook.handleUnlinkedInstallation({
      event: 'team',
      installationId: INSTALL_ID,
      deliveryId: 'd-1',
      action: 'created',
      accountLogin: 'acme',
    });

    assert.equal(body.note, 'unlinked_installation');
    assert.equal(platformEvents.length, 1);
    assert.equal(platformEvents[0].eventType, 'installation.webhook_unlinked');
    assert.equal(platformEvents[0].tenantId, null);
    assert.equal(platformEvents[0].payload.adminLinkRequired, true);
    assert.equal(platformEvents[0].payload.installationId, INSTALL_ID);
  });

  it('handlePendingInstallationLink queues installation.pending_link', async () => {
    const body = await webhook.handlePendingInstallationLink({
      installationId: INSTALL_ID,
      deliveryId: 'd-2',
      senderLogin: 'alice',
      accountLogin: 'acme',
      installerEmail: 'alice@acme.com',
    });

    assert.equal(body.note, 'pending_admin_link');
    assert.equal(platformEvents[0].eventType, 'installation.pending_link');
    assert.equal(platformEvents[0].payload.adminLinkRequired, true);
    assert.equal(platformEvents[0].payload.installerEmail, 'alice@acme.com');
    assert.equal(platformEvents[0].payload.installationId, INSTALL_ID);
  });

  it('team webhook for unlinked installation returns 200 and does not write teams', async () => {
    let teamWrites = 0;
    require.cache[tenantModelsPath].exports.getTenantModels = () => {
      throw new Error('getTenantModels must not run for unlinked installs');
    };

    // Re-require after auth stays null
    delete require.cache[webhookPath];
    webhook = require('../controllers/webhook');

    const req = {
      headers: {
        'x-github-event': 'team',
        'x-github-delivery': 'del-unlinked',
      },
      body: {
        action: 'created',
        team: {
          node_id: 'T_1',
          name: 'Eng',
          slug: 'eng',
          privacy: 'closed',
          members_count: 1,
          repos_count: 0,
        },
        organization: { id: 42, login: 'acme' },
        installation: { id: INSTALL_ID },
      },
    };

    let statusCode;
    let responseBody;
    await webhook.handleWebhook(
      req,
      {
        status: (code) => {
          statusCode = code;
          return {
            json: (data) => {
              responseBody = data;
            },
          };
        },
      },
      () => {}
    );

    // Express-style: status(200).json(...) — our controller uses res.status(200).json
    // If status helper missing, some paths call res.status(200).json — ensure both work.
    if (statusCode === undefined) {
      // handleWebhook uses res.status(200).json — mock may need chained API only
    }

    assert.equal(statusCode, 200);
    assert.equal(responseBody.note, 'unlinked_installation');
    assert.equal(platformEvents.length, 1);
    assert.equal(teamWrites, 0);
  });

  it('linked team webhook writes tenantId on Team upsert', async () => {
    require.cache[authRoutingPath].exports.getTenantByInstallationId = async () => TENANT_A;

    let capturedUpdate;
    require.cache[tenantModelsPath].exports.getTenantModels = (tenantId) => ({
      tenantId: String(tenantId),
      Team: {
        findOneAndUpdate: async (_filter, update) => {
          capturedUpdate = update;
          return update;
        },
        findOne: async () => null,
        deleteOne: async () => ({}),
      },
      TeamMember: {
        deleteMany: async () => ({}),
        countDocuments: async () => 0,
      },
      InstallationSummaryJob: {
        findOne: () => ({ sort: async () => null }),
      },
      RepositoryData: {},
      GitHubSecurityEvent: {},
    });

    delete require.cache[webhookPath];
    webhook = require('../controllers/webhook');

    const req = {
      headers: {
        'x-github-event': 'team',
        'x-github-delivery': 'del-linked',
      },
      body: {
        action: 'created',
        team: {
          node_id: 'T_1',
          name: 'Eng',
          slug: 'eng',
          privacy: 'closed',
          members_count: 1,
          repos_count: 0,
        },
        organization: { id: 42, login: 'acme' },
        installation: { id: INSTALL_ID },
      },
    };

    let statusCode;
    await webhook.handleWebhook(
      req,
      {
        status: (code) => {
          statusCode = code;
          return { json: () => {} };
        },
      },
      () => {}
    );

    assert.equal(statusCode, 200);
    assert.equal(String(capturedUpdate.tenantId), TENANT_A);
  });

  it('triggerIncrementalRefresh persists tenantId on summary job', async () => {
    let capturedFilter;
    let capturedUpdate;
    const models = {
      InstallationSummaryJob: {
        findOne: async () => null,
        findOneAndUpdate: async (filter, update) => {
          capturedFilter = filter;
          capturedUpdate = update;
          return { _id: 'job-xyz' };
        },
        findByIdAndUpdate: async () => ({}),
      },
    };

    await webhook.triggerIncrementalRefresh(models, TENANT_A, INSTALL_ID, 42, 'acme', 'Organization');

    assert.equal(capturedFilter.tenantId, TENANT_A);
    assert.equal(capturedUpdate.$setOnInsert.tenantId, TENANT_A);
    // …and NOT in $set as well. MongoDB rejects an update whose operators both
    // write the same path ("Updating the path 'tenantId' would create a conflict
    // at 'tenantId'"), which took down every summary-job upsert. The filter plus
    // $setOnInsert is what actually persists it.
    assert.ok(
      !('tenantId' in capturedUpdate.$set),
      'tenantId must not appear in $set — it conflicts with $setOnInsert'
    );
  });
});
