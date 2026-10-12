const path = require('path');
const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const createError = require('../utils/createError');

const TENANT_A = '674a1b2c3d4e5f6789012345';
const TENANT_B = '674a1b2c3d4e5f6789012346';
const INSTALL_ID = 424242;

const githubTokenHelperPath = path.resolve(__dirname, '../helpers/githubTokenHelper.js');
const githubControllerPath = path.resolve(__dirname, '../controllers/github.js');

function loadGithubController() {
  require.cache[githubTokenHelperPath] = {
    id: githubTokenHelperPath,
    filename: githubTokenHelperPath,
    loaded: true,
    exports: { getInstallationToken: async () => 'test-token' },
  };
  delete require.cache[githubControllerPath];
  return require('../controllers/github');
}

describe('github installation route scoping', () => {
  let githubController;
  let tenantScope;
  let originalAssert;
  let originalList;
  let originalAxiosGet;

  beforeEach(() => {
    tenantScope = require('../helpers/tenantScope');
    originalAssert = tenantScope.assertInstallationBelongsToTenant;
    originalList = tenantScope.listInstallationsForTenant;
    githubController = loadGithubController();
  });

  afterEach(() => {
    tenantScope.assertInstallationBelongsToTenant = originalAssert;
    tenantScope.listInstallationsForTenant = originalList;
    delete require.cache[githubTokenHelperPath];
    delete require.cache[githubControllerPath];
    if (originalAxiosGet) {
      require('axios').get = originalAxiosGet;
      originalAxiosGet = undefined;
    }
  });

  it('listRepos blocks cross-tenant installation access with 403', async () => {
    tenantScope.assertInstallationBelongsToTenant = async (_installationId, tenantId) => {
      if (String(tenantId) === TENANT_B) {
        throw createError(403, 'Installation does not belong to your organization');
      }
      return { installationId: INSTALL_ID };
    };

    const req = {
      params: { installationId: String(INSTALL_ID) },
      tenant: { id: TENANT_B, role: 'admin' },
    };

    let err;
    await githubController.listRepos(req, { json: () => {} }, (e) => {
      err = e;
    });

    assert.equal(err?.statusCode, 403);
  });

  it('listRepos proceeds when installation belongs to tenant', async () => {
    tenantScope.assertInstallationBelongsToTenant = async () => ({
      installationId: INSTALL_ID,
    });

    const axios = require('axios');
    originalAxiosGet = axios.get;
    axios.get = async () => ({
      data: { repositories: [] },
      headers: {},
    });

    const req = {
      params: { installationId: String(INSTALL_ID) },
      tenant: { id: TENANT_A, role: 'admin' },
    };

    let err;
    let body;
    await githubController.listRepos(
      req,
      { json: (data) => { body = data; } },
      (e) => { err = e; }
    );

    assert.equal(err, undefined);
    assert.deepEqual(body, []);
  });

  it('listInstallationsForUser returns only tenant-scoped installs', async () => {
    const tenantInstall = { installationId: INSTALL_ID, account: { login: 'acme' } };
    tenantScope.listInstallationsForTenant = async (tenantId) =>
      tenantId === TENANT_A ? [tenantInstall] : [];

    const req = {
      user: { login: 'admin', role: 'admin' },
      tenant: { id: TENANT_A, role: 'admin' },
    };

    let payload;
    await githubController.listInstallationsForUser(
      req,
      { json: (data) => { payload = data; } },
      () => {}
    );

    assert.equal(payload.installations.length, 1);
    assert.equal(payload.installations[0].installationId, INSTALL_ID);
  });

  it('listInstallationsForUser returns empty list when tenant is absent', async () => {
    tenantScope.listInstallationsForTenant = async () => {
      throw new Error('should not list without tenant');
    };

    const req = {
      user: { login: 'user', role: 'member' },
      tenant: undefined,
    };

    let payload;
    await githubController.listInstallationsForUser(
      req,
      { json: (data) => { payload = data; } },
      () => {}
    );

    assert.deepEqual(payload.installations, []);
  });

  it('checkInstallationStatus returns false when tenant has no installations (admin)', async () => {
    tenantScope.listInstallationsForTenant = async () => [];

    const req = {
      user: { login: 'admin', role: 'admin' },
      tenant: { id: TENANT_A, role: 'admin' },
    };

    let payload;
    await githubController.checkInstallationStatus(
      req,
      { status() { return this; }, json: (data) => { payload = data; } },
      () => {}
    );

    assert.equal(payload.hasInstallation, false);
  });

  it('checkInstallationStatus returns false for member when tenant has no installations', async () => {
    tenantScope.listInstallationsForTenant = async () => [];

    const req = {
      user: { login: 'member-user', role: 'member' },
      tenant: { id: TENANT_A, role: 'member' },
    };

    let payload;
    await githubController.checkInstallationStatus(
      req,
      { status() { return this; }, json: (data) => { payload = data; } },
      () => {}
    );

    assert.equal(payload.hasInstallation, false);
  });

  it('checkInstallationStatus returns true for member when tenant has installations', async () => {
    tenantScope.listInstallationsForTenant = async () => [
      { installationId: INSTALL_ID, account: { login: 'acme' } },
    ];

    const req = {
      user: { login: 'member-user', role: 'member' },
      tenant: { id: TENANT_A, role: 'member' },
    };

    let payload;
    await githubController.checkInstallationStatus(
      req,
      { status() { return this; }, json: (data) => { payload = data; } },
      () => {}
    );

    assert.equal(payload.hasInstallation, true);
  });

  it('checkInstallationStatus returns true for admin when tenant has installations', async () => {
    tenantScope.listInstallationsForTenant = async () => [
      { installationId: INSTALL_ID, account: { login: 'acme' } },
    ];

    const req = {
      user: { login: 'admin', role: 'admin' },
      tenant: { id: TENANT_A, role: 'admin' },
    };

    let payload;
    await githubController.checkInstallationStatus(
      req,
      { status() { return this; }, json: (data) => { payload = data; } },
      () => {}
    );

    assert.equal(payload.hasInstallation, true);
  });

  // The dashboard waits on a specific install after the GitHub redirect; an admin
  // adding a second org already has `hasInstallation: true`, so that is not enough.
  it('checkInstallationStatus reports whether a requested installation is linked yet', async () => {
    tenantScope.listInstallationsForTenant = async () => [
      { installationId: INSTALL_ID, account: { login: 'acme' } },
    ];
    const check = async (installationId) => {
      let payload;
      await githubController.checkInstallationStatus(
        {
          user: { login: 'admin', role: 'admin' },
          tenant: { id: TENANT_A, role: 'admin' },
          query: { installationId },
        },
        { status() { return this; }, json: (data) => { payload = data; } },
        () => {}
      );
      return payload;
    };

    const linked = await check(String(INSTALL_ID));
    assert.equal(linked.linked, true);
    assert.equal(linked.hasInstallation, true);

    const notYet = await check('999999');
    assert.equal(notYet.linked, false);
    assert.equal(notYet.hasInstallation, true);
  });

  it('checkInstallationStatus omits `linked` when no installation is asked about', async () => {
    tenantScope.listInstallationsForTenant = async () => [];

    let payload;
    await githubController.checkInstallationStatus(
      { user: { login: 'admin', role: 'admin' }, tenant: { id: TENANT_A, role: 'admin' } },
      { status() { return this; }, json: (data) => { payload = data; } },
      () => {}
    );

    assert.equal('linked' in payload, false);
  });
});

describe('listInstallationsForTenant', () => {
  it('returns only installations indexed for the tenant', async () => {
    const { listInstallationsForTenant } = require('../helpers/tenantScope');
    const tenantAInstall = { installationId: 1 };

    const installations = await listInstallationsForTenant(TENANT_A, {
      getControlModels: () => ({
        InstallationIndex: {
          find: () => ({
            select: () => ({
              lean: async () => [{ githubInstallationId: 1 }],
            }),
          }),
        },
      }),
      getTenantModels: (tenantId) => ({
        Installation: {
          find: () => ({
            lean: async () => (tenantId === TENANT_A ? [tenantAInstall] : []),
          }),
        },
      }),
    });

    assert.deepEqual(installations, [tenantAInstall]);
  });

  it('returns empty array when tenantId is missing', async () => {
    const { listInstallationsForTenant } = require('../helpers/tenantScope');
    const result = await listInstallationsForTenant(null);
    assert.deepEqual(result, []);
  });
});

describe('cross-tenant installation access', () => {
  it('Org B cannot access Org A installation via assertInstallationBelongsToTenant', async () => {
    const { assertInstallationBelongsToTenant } = require('../helpers/tenantScope');

    await assert.rejects(
      () =>
        assertInstallationBelongsToTenant(INSTALL_ID, TENANT_B, {
          getTenantByInstallationId: async () => TENANT_A,
          getTenantModels: () => ({
            Installation: {
              findOne: () => ({
                lean: async () => ({ installationId: INSTALL_ID }),
              }),
            },
          }),
        }),
      (err) => err.statusCode === 403
    );
  });
});
