const path = require('path');
const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const createError = require('../utils/createError');

const TENANT_A = '674a1b2c3d4e5f6789012345';
const TENANT_B = '674a1b2c3d4e5f6789012346';
const INSTALL_ID = 9001;

const installationA = {
  installationId: INSTALL_ID,
  account: { id: 42, login: 'acme-org', type: 'Organization' },
};

describe('repositoryController tenant scoping', () => {
  let tenantScope;
  let repositoryController;
  let originalAssert;

  beforeEach(() => {
    tenantScope = require('../helpers/tenantScope');
    originalAssert = tenantScope.assertInstallationBelongsToTenant;
    delete require.cache[require.resolve('../controllers/repositoryController')];
    repositoryController = require('../controllers/repositoryController');
  });

  afterEach(() => {
    tenantScope.assertInstallationBelongsToTenant = originalAssert;
    delete require.cache[require.resolve('../controllers/repositoryController')];
  });

  it('getRepositoryBranches returns 403 for cross-tenant installation', async () => {
    tenantScope.assertInstallationBelongsToTenant = async (_id, tenantId) => {
      if (String(tenantId) === TENANT_B) {
        throw createError(403, 'Installation does not belong to your organization');
      }
      return installationA;
    };

    const req = {
      params: { installationId: String(INSTALL_ID), repositoryName: 'api' },
      tenant: { id: TENANT_B },
      user: { login: 'devuser' },
      models: { RepositoryData: { findOne: async () => null } },
    };

    let err;
    await repositoryController.getRepositoryBranches(req, { json: () => {} }, (e) => {
      err = e;
    });

    assert.equal(err?.statusCode, 403);
  });

  it('getRepositoryBranches queries by installation account login', async () => {
    tenantScope.assertInstallationBelongsToTenant = async () => installationA;

    let capturedQuery;
    const req = {
      params: { installationId: String(INSTALL_ID), repositoryName: 'api' },
      tenant: { id: TENANT_A },
      user: { login: 'devuser' },
      models: {
        RepositoryData: {
          findOne: async (query) => {
            capturedQuery = query;
            return {
              repositoryName: 'api',
              owner: 'acme-org',
              branches: [{ name: 'main' }],
            };
          },
        },
      },
    };

    let body;
    await repositoryController.getRepositoryBranches(
      req,
      { json: (data) => { body = data; } },
      () => {}
    );

    assert.deepEqual(capturedQuery, {
      tenantId: TENANT_A,
      installationId: INSTALL_ID,
      login: 'acme-org',
      repositoryName: 'api',
    });
    assert.equal(body.totalBranches, 1);
  });

  it('deleteRepositoryData scopes delete to tenant installation', async () => {
    tenantScope.assertInstallationBelongsToTenant = async () => installationA;

    let capturedQuery;
    const req = {
      params: { installationId: String(INSTALL_ID), repositoryName: 'api' },
      tenant: { id: TENANT_A },
      user: { login: 'devuser' },
      models: {
        RepositoryData: {
          deleteOne: async (query) => {
            capturedQuery = query;
            return { deletedCount: 1 };
          },
        },
      },
    };

    await repositoryController.deleteRepositoryData(req, { json: () => {} }, () => {});

    assert.deepEqual(capturedQuery, {
      tenantId: TENANT_A,
      installationId: INSTALL_ID,
      login: 'acme-org',
      repositoryName: 'api',
    });
  });
});

describe('installationSummaryController tenant scoping', () => {
  const summaryQueuePath = path.resolve(__dirname, '../queues/summaryQueue.js');
  const controllerPath = path.resolve(__dirname, '../controllers/installationSummaryController.js');
  let tenantScope;
  let originalAssert;
  let controller;

  beforeEach(() => {
    tenantScope = require('../helpers/tenantScope');
    originalAssert = tenantScope.assertInstallationBelongsToTenant;

    require.cache[summaryQueuePath] = {
      id: summaryQueuePath,
      filename: summaryQueuePath,
      loaded: true,
      exports: {
        add: async () => ({ id: 'bull-job-1' }),
        getJob: async () => null,
      },
    };

    delete require.cache[controllerPath];
    controller = require('../controllers/installationSummaryController');
  });

  afterEach(() => {
    tenantScope.assertInstallationBelongsToTenant = originalAssert;
    delete require.cache[summaryQueuePath];
    delete require.cache[controllerPath];
  });

  it('startSummaryJob blocks cross-tenant installation', async () => {
    tenantScope.assertInstallationBelongsToTenant = async (_id, tenantId) => {
      if (String(tenantId) === TENANT_B) {
        throw createError(403, 'Installation does not belong to your organization');
      }
      return installationA;
    };

    const req = {
      params: { installationId: String(INSTALL_ID) },
      tenant: { id: TENANT_B },
      tenantId: TENANT_B,
      user: { login: 'admin' },
      query: {},
      models: {
        InstallationSummaryJob: {
          findOneAndUpdate: async () => ({ _id: 'job-1', status: 'pending' }),
          findByIdAndUpdate: async () => ({}),
        },
      },
    };

    let err;
    await controller.startSummaryJob(req, { json: () => {} }, (e) => {
      err = e;
    });

    assert.equal(err?.statusCode, 403);
  });

  it('startSummaryJob writes tenantId on job upsert', async () => {
    tenantScope.assertInstallationBelongsToTenant = async () => installationA;

    let capturedFilter;
    let capturedUpdate;
    const req = {
      params: { installationId: String(INSTALL_ID) },
      tenant: { id: TENANT_A },
      tenantId: TENANT_A,
      user: { login: 'admin' },
      query: {},
      models: {
        InstallationSummaryJob: {
          findOne: async () => null,
          findOneAndUpdate: async (filter, update) => {
            capturedFilter = filter;
            capturedUpdate = update;
            return { _id: 'job-1', status: 'pending' };
          },
          findByIdAndUpdate: async () => ({}),
        },
      },
    };

    await controller.startSummaryJob(req, { json: () => {} }, () => {});

    assert.deepEqual(capturedFilter, {
      tenantId: TENANT_A,
      installationId: INSTALL_ID,
      accountId: 42,
    });
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

  it('getJobStatus blocks job tied to another tenant installation', async () => {
    tenantScope.assertInstallationBelongsToTenant = async (_id, tenantId) => {
      if (String(tenantId) === TENANT_B) {
        throw createError(403, 'Installation does not belong to your organization');
      }
      return installationA;
    };

    const req = {
      params: { jobId: 'job-abc' },
      tenant: { id: TENANT_B },
      tenantId: TENANT_B,
      models: {
        InstallationSummaryJob: {
          findOne: async () => ({
            installationId: INSTALL_ID,
            status: 'completed',
            summary: {},
          }),
        },
      },
    };

    let err;
    await controller.getJobStatus(req, { json: () => {} }, (e) => {
      err = e;
    });

    assert.equal(err?.statusCode, 403);
  });

  it('getJobStatus queries job by tenantId', async () => {
    tenantScope.assertInstallationBelongsToTenant = async () => installationA;

    let capturedQuery;
    const req = {
      params: { jobId: 'job-abc' },
      tenant: { id: TENANT_A },
      tenantId: TENANT_A,
      models: {
        InstallationSummaryJob: {
          findOne: async (query) => {
            capturedQuery = query;
            return {
              installationId: INSTALL_ID,
              status: 'completed',
              summary: {},
            };
          },
        },
      },
    };

    await controller.getJobStatus(req, { json: () => {} }, () => {});

    assert.deepEqual(capturedQuery, { _id: 'job-abc', tenantId: TENANT_A });
  });
});

describe('repositoryQuery helper', () => {
  it('builds tenant + installation scoped query', () => {
    const { repositoryQuery } = require('../controllers/repositoryController');
    assert.deepEqual(
      repositoryQuery({
        tenantId: TENANT_A,
        installationId: 1,
        accountLogin: 'acme-org',
        repositoryName: 'svc',
      }),
      { tenantId: TENANT_A, installationId: 1, login: 'acme-org', repositoryName: 'svc' }
    );
  });
});
