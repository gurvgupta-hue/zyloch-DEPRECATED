const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');

describe('licenseLimits', () => {
  let licenseLimits;
  let licenseEntitlements;
  let controlModels;
  let tenantModels;
  let originalResolve;
  let originalGetControl;
  let originalGetTenant;

  function reloadLicenseLimits() {
    delete require.cache[require.resolve('../services/licenseLimits')];
    licenseLimits = require('../services/licenseLimits');
  }

  beforeEach(() => {
    delete require.cache[require.resolve('../services/licenseLimits')];
    delete require.cache[require.resolve('../services/licenseEntitlements')];
    delete require.cache[require.resolve('../db/controlModels')];
    delete require.cache[require.resolve('../db/tenantModels')];

    licenseEntitlements = require('../services/licenseEntitlements');
    controlModels = require('../db/controlModels');
    tenantModels = require('../db/tenantModels');
    originalResolve = licenseEntitlements.resolveTenantEntitlements;
    originalGetControl = controlModels.getControlModels;
    originalGetTenant = tenantModels.getTenantModels;

    licenseLimits = require('../services/licenseLimits');
  });

  afterEach(() => {
    licenseEntitlements.resolveTenantEntitlements = originalResolve;
    controlModels.getControlModels = originalGetControl;
    tenantModels.getTenantModels = originalGetTenant;
    delete require.cache[require.resolve('../services/licenseLimits')];
  });

  it('readLimit floors values, treats negatives as unlimited, absent as 0', () => {
    assert.equal(licenseLimits.readLimit({ maxRepos: 10.9 }, 'maxRepos'), 10);
    // -1 is the UNLIMITED sentinel (per-seat / Enterprise plans), not "zero".
    assert.equal(licenseLimits.readLimit({ maxRepos: -1 }, 'maxRepos'), Number.POSITIVE_INFINITY);
    assert.equal(licenseLimits.readLimit({}, 'maxRepos'), 0);
    assert.equal(licenseLimits.readLimit({ maxRepos: 'abc' }, 'maxRepos'), 0);
  });

  it('an absent daily scan ceiling means no daily ceiling, not zero', () => {
    // A plan stating only a monthly figure must not resolve to 0 scans/day,
    // which would block every scan.
    assert.equal(
      licenseLimits.readPlanLimit({ maxScansPerMonth: 100 }, 'maxScansPerDay'),
      Number.POSITIVE_INFINITY
    );
    assert.equal(licenseLimits.readPlanLimit({ maxScansPerDay: 150 }, 'maxScansPerDay'), 150);
  });

  it('capReposToLimit truncates to plan maxRepos', () => {
    const repos = [{ id: 1 }, { id: 2 }, { id: 3 }];
    assert.deepEqual(licenseLimits.capReposToLimit(repos, 2), [{ id: 1 }, { id: 2 }]);
    assert.deepEqual(licenseLimits.capReposToLimit(repos, 0), []);
    assert.deepEqual(licenseLimits.capReposToLimit(repos, 10), repos);
  });

  it('resolveTenantLimits maps plan entitlements dynamically', async () => {
    licenseEntitlements.resolveTenantEntitlements = async () => ({
      tenantId: 't1',
      planId: 'basic',
      active: true,
      entitlements: { maxRepos: 10, maxUsers: 5, maxScansPerMonth: 100 },
    });
    reloadLicenseLimits();

    const limits = await licenseLimits.resolveTenantLimits('t1');
    assert.equal(limits.planId, 'basic');
    assert.equal(limits.maxRepos, 10);
    assert.equal(limits.maxUsers, 5);
    assert.equal(limits.maxScansPerMonth, 100);
  });

  it('assertRepoCapacity throws LICENSE_LIMIT_EXCEEDED when over maxRepos', async () => {
    await assert.rejects(
      () =>
        licenseLimits.assertRepoCapacity('t1', {
          additional: 1,
          currentCount: 10,
          entitlements: { maxRepos: 10 },
          active: true,
        }),
      (err) =>
        err.statusCode === 403 &&
        err.code === 'LICENSE_LIMIT_EXCEEDED' &&
        err.limitKey === 'maxRepos'
    );
  });

  it('assertRepoCapacity allows when under maxRepos', async () => {
    const result = await licenseLimits.assertRepoCapacity('t1', {
      additional: 1,
      currentCount: 9,
      entitlements: { maxRepos: 10 },
      active: true,
    });
    assert.equal(result.limit, 10);
    assert.equal(result.current, 9);
  });

  it('assertUserCapacity throws when at maxUsers', async () => {
    tenantModels.getTenantModels = () => ({
      User: { countDocuments: async () => 5 },
    });
    reloadLicenseLimits();

    await assert.rejects(
      () =>
        licenseLimits.assertUserCapacity('t1', {
          entitlements: { maxUsers: 5 },
          active: true,
        }),
      (err) => err.code === 'LICENSE_LIMIT_EXCEEDED' && err.limitKey === 'maxUsers'
    );
  });

  it('assertScanCapacity throws when monthly scans exhausted', async () => {
    const monthKey = licenseLimits.currentMonthKey();
    controlModels.getControlModels = () => ({
      TenantMetrics: {
        findOne: () => ({
          lean: async () => ({
            scanMonthKey: monthKey,
            scanCountThisMonth: 100,
          }),
        }),
      },
    });
    reloadLicenseLimits();

    await assert.rejects(
      () =>
        licenseLimits.assertScanCapacity('t1', {
          entitlements: { maxScansPerMonth: 100 },
          active: true,
        }),
      (err) =>
        err.code === 'LICENSE_LIMIT_EXCEEDED' && err.limitKey === 'maxScansPerMonth'
    );
  });

  it('assertScanCapacity allows when under monthly limit', async () => {
    controlModels.getControlModels = () => ({
      TenantMetrics: {
        findOne: () => ({
          lean: async () => ({
            scanMonthKey: licenseLimits.currentMonthKey(),
            scanCountThisMonth: 3,
          }),
        }),
      },
    });
    reloadLicenseLimits();

    const result = await licenseLimits.assertScanCapacity('t1', {
      entitlements: { maxScansPerMonth: 100 },
      active: true,
    });
    assert.equal(result.current, 3);
    assert.equal(result.limit, 100);
  });

  it('pro plan maxRepos differs from free (dynamic, not hardcoded)', async () => {
    licenseEntitlements.resolveTenantEntitlements = async () => ({
      tenantId: 't1',
      planId: 'pro',
      active: true,
      entitlements: { maxRepos: 200, maxUsers: 50, maxScansPerMonth: 2000 },
    });
    reloadLicenseLimits();

    const limits = await licenseLimits.resolveTenantLimits('t1');
    assert.equal(limits.maxRepos, 200);
    assert.notEqual(limits.maxRepos, 1000);
  });
});
