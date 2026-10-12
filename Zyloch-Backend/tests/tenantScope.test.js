const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { assertInstallationBelongsToTenant } = require('../helpers/tenantScope');

const TENANT_A = '674a1b2c3d4e5f6789012345';
const TENANT_B = '674a1b2c3d4e5f6789012346';
const INSTALL_ID = 12345;

const installationDoc = {
  installationId: INSTALL_ID,
  account: { id: 1, login: 'acme', type: 'Organization' },
};

function makeDeps({ ownerTenantId = TENANT_A, installation = installationDoc } = {}) {
  return {
    getTenantByInstallationId: async () => ownerTenantId,
    getTenantModels: () => ({
      Installation: {
        findOne: () => ({
          lean: async () =>
            installation && installation.installationId === INSTALL_ID ? installation : null,
        }),
      },
    }),
  };
}

describe('assertInstallationBelongsToTenant', () => {
  it('returns installation doc when tenant matches', async () => {
    const doc = await assertInstallationBelongsToTenant(INSTALL_ID, TENANT_A, makeDeps());
    assert.deepEqual(doc, installationDoc);
  });

  it('returns 403 when installation belongs to another tenant', async () => {
    await assert.rejects(
      () =>
        assertInstallationBelongsToTenant(INSTALL_ID, TENANT_B, makeDeps({ ownerTenantId: TENANT_A })),
      (err) => {
        assert.equal(err.statusCode, 403);
        assert.match(err.message, /does not belong/i);
        return true;
      }
    );
  });

  it('returns 404 when installation id is unknown in control index', async () => {
    const deps = makeDeps();
    deps.getTenantByInstallationId = async () => null;

    await assert.rejects(
      () => assertInstallationBelongsToTenant(INSTALL_ID, TENANT_A, deps),
      (err) => {
        assert.equal(err.statusCode, 404);
        assert.match(err.message, /not found/i);
        return true;
      }
    );
  });

  it('returns 404 when index exists but tenant DB has no installation row', async () => {
    await assert.rejects(
      () =>
        assertInstallationBelongsToTenant(INSTALL_ID, TENANT_A, makeDeps({ installation: null })),
      (err) => {
        assert.equal(err.statusCode, 404);
        return true;
      }
    );
  });

  it('returns 404 for invalid installation id', async () => {
    await assert.rejects(
      () => assertInstallationBelongsToTenant('not-a-number', TENANT_A, makeDeps()),
      (err) => err.statusCode === 404
    );
  });
});
