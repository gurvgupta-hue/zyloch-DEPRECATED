const path = require('path');
const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const createError = require('../utils/createError');

const TENANT_A = '674a1b2c3d4e5f6789012345';

describe('KAN-43 getLicense controller', () => {
  const licenseLimitsPath = path.resolve(__dirname, '../services/licenseLimits.js');
  const licenseEntitlementsPath = path.resolve(__dirname, '../services/licenseEntitlements.js');
  const controlModelsPath = path.resolve(__dirname, '../db/controlModels.js');
  const controllerPath = path.resolve(__dirname, '../controllers/license.js');

  beforeEach(() => {
    require.cache[licenseLimitsPath] = {
      id: licenseLimitsPath,
      filename: licenseLimitsPath,
      loaded: true,
      exports: {
        countTenantUsers: async () => 2,
        countTenantRepos: async () => 1,
        getMonthlyScanUsage: async () => ({ count: 0, monthKey: '2026-07' }),
        getDailyScanUsage: async () => ({ count: 0, dayKey: '2026-07-15' }),
      },
    };
    require.cache[licenseEntitlementsPath] = {
      id: licenseEntitlementsPath,
      filename: licenseEntitlementsPath,
      loaded: true,
      exports: {
        resolveTenantEntitlements: async () => ({
          planId: 'basic',
          plan: { name: 'Free' },
          status: 'active',
          active: true,
          entitlements: {
            maxUsers: 5,
            maxRepos: 10,
            maxScansPerMonth: 50,
            maxScansPerDay: -1,
          },
        }),
        // Real implementation: unlimited (-1 / Infinity) serialises as null.
        presentLimit: (value) => {
          const n = Number(value);
          if (!Number.isFinite(n)) return null;
          return n < 0 ? null : n;
        },
      },
    };
  });

  afterEach(() => {
    delete require.cache[licenseLimitsPath];
    delete require.cache[licenseEntitlementsPath];
    delete require.cache[controlModelsPath];
    delete require.cache[controllerPath];
  });

  it('returns 404 when tenant has no license document', async () => {
    require.cache[controlModelsPath] = {
      id: controlModelsPath,
      filename: controlModelsPath,
      loaded: true,
      exports: {
        getControlModels: () => ({
          TenantLicense: { findOne: () => ({ lean: async () => null }) },
        }),
      },
    };
    delete require.cache[controllerPath];
    const { getLicense } = require('../controllers/license');

    const req = { tenantId: TENANT_A, license: null };
    let err;
    await getLicense(req, { json: () => {} }, (e) => {
      err = e;
    });
    assert.equal(err?.statusCode, 404);
  });

  it('returns license with usage for owning tenant', async () => {
    require.cache[controlModelsPath] = {
      id: controlModelsPath,
      filename: controlModelsPath,
      loaded: true,
      exports: {
        getControlModels: () => ({
          TenantLicense: {
            findOne: () => ({
              lean: async () => ({
                tenantId: TENANT_A,
                planId: 'basic',
                status: 'active',
                startsAt: new Date(),
                expiresAt: null,
              }),
            }),
          },
        }),
      },
    };
    delete require.cache[controllerPath];
    const { getLicense } = require('../controllers/license');

    const req = {
      tenantId: TENANT_A,
      license: {
        planId: 'basic',
        plan: { name: 'Free' },
        status: 'active',
        active: true,
        entitlements: { maxUsers: 5, maxRepos: 10, maxScansPerMonth: 50 },
      },
    };
    let body;
    await getLicense(req, { json: (data) => { body = data; } }, () => {});
    assert.equal(body.success, true);
    assert.equal(body.license.planId, 'basic');
    assert.equal(body.license.usage.users.current, 2);
    assert.equal(body.license.usage.users.max, 5);
    // Unlimited daily ceiling surfaces as null, not 0 or -1.
    assert.equal(body.license.usage.scansToday.max, null);
    assert.equal(body.license.usage.scansToday.current, 0);
  });
});

describe('KAN-45 members invite capacity', () => {
  const membersPath = path.resolve(__dirname, '../controllers/members.js');
  const licenseLimitsPath = path.resolve(__dirname, '../services/licenseLimits.js');

  afterEach(() => {
    delete require.cache[membersPath];
    delete require.cache[licenseLimitsPath];
  });

  it('inviteMember returns 403 when seat limit exceeded', async () => {
    require.cache[licenseLimitsPath] = {
      id: licenseLimitsPath,
      filename: licenseLimitsPath,
      loaded: true,
      exports: {
        assertUserCapacity: async () => {
          throw Object.assign(createError(403, 'License limit exceeded for maxUsers: 5/5'), {
            code: 'LICENSE_LIMIT_EXCEEDED',
            current: 5,
            limit: 5,
          });
        },
        countTenantUsers: async () => 5,
        syncUsageMetrics: async () => {},
      },
    };
    delete require.cache[membersPath];
    const { inviteMember } = require('../controllers/members');

    const req = {
      tenantId: TENANT_A,
      user: { id: 'admin1' },
      license: { active: true, entitlements: { maxUsers: 5 } },
      body: { email: 'new@acme.com' },
      models: {
        User: {
          findOne: () => ({ lean: async () => null }),
        },
        MemberInvite: {
          findOne: () => ({ lean: async () => null }),
          create: async () => ({
            _id: 'inv1',
            email: 'new@acme.com',
            status: 'pending',
            expiresAt: new Date(),
          }),
        },
      },
    };
    let err;
    await inviteMember(req, { status: () => ({ json: () => {} }) }, (e) => {
      err = e;
    });
    assert.equal(err?.statusCode, 403);
    assert.match(String(err?.message || ''), /seat limit/i);
  });
});
