const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const {
  evaluateTenantStanding,
  resolveTenantAccess,
  TENANT_ACCESS_ERRORS,
} = require('../services/tenantAccess');
const {
  entitledScanners,
  normalizeScannerKey,
  SCANNER_KEYS,
} = require('../services/licenseEntitlements');
const { requireActiveLicense } = require('../middleware/requireEntitlement');
const { resolveEntitledScanRequest } = require('../controllers/scans');

const TENANT_A = '674a1b2c3d4e5f6789012345';

describe('MT-05.4 suspended tenants lose access', () => {
  it('allows an active organization', () => {
    const standing = evaluateTenantStanding({ isActive: true, provisionStatus: 'active' });
    assert.equal(standing.allowed, true);
  });

  it('blocks a deactivated organization', () => {
    const standing = evaluateTenantStanding({ isActive: false, provisionStatus: 'active' });
    assert.equal(standing.allowed, false);
    assert.equal(standing.code, TENANT_ACCESS_ERRORS.ORG_INACTIVE);
  });

  for (const status of ['suspended', 'offboarding', 'offboarded']) {
    it(`blocks a ${status} organization`, () => {
      const standing = evaluateTenantStanding({ isActive: true, provisionStatus: status });
      assert.equal(standing.allowed, false, `${status} must not serve requests`);
      assert.equal(standing.code, TENANT_ACCESS_ERRORS.ORG_SUSPENDED);
    });
  }

  it('blocks a missing organization', () => {
    const standing = evaluateTenantStanding(null);
    assert.equal(standing.allowed, false);
    assert.equal(standing.code, TENANT_ACCESS_ERRORS.ORG_NOT_FOUND);
  });

  it('does not lock out a document with no provisionStatus (legacy safety)', () => {
    assert.equal(evaluateTenantStanding({ isActive: true }).allowed, true);
  });

  it('resolves standing and license together', async () => {
    const access = await resolveTenantAccess(TENANT_A, {
      getControlModels: () => ({
        Organization: {
          findById: () => ({
            select: () => ({
              lean: async () => ({ isActive: true, provisionStatus: 'suspended' }),
            }),
          }),
        },
      }),
      resolveTenantEntitlements: async () => ({ active: true, entitlements: {} }),
    });

    assert.equal(access.standing.allowed, false);
    assert.equal(access.license.active, true, 'license still resolved for reporting');
  });
});

describe('MT-05.3 requireActiveLicense gates on the resolved license', () => {
  function run(license) {
    return new Promise((resolve) => {
      requireActiveLicense({ license }, {}, (err) => resolve(err));
    });
  }

  it('passes an active license', async () => {
    assert.equal(await run({ active: true }), undefined);
  });

  it('rejects an inactive license', async () => {
    const err = await run({ active: false });
    assert.equal(err.statusCode, 403);
    assert.match(err.message, /not active/i);
  });

  it('rejects a missing license', async () => {
    assert.equal((await run(undefined)).statusCode, 403);
  });
});

describe('MT-05.2 scan requests are narrowed to entitled scanners', () => {
  const FREE = { scanners: ['docker', 'workflow', 'secret_scanner'] };
  const PRO = { scanners: ['all'] };

  it('expands "all" to every scanner on an unlimited plan', () => {
    assert.deepEqual(entitledScanners(PRO).sort(), [...SCANNER_KEYS].sort());
  });

  it('expands "all" to only the plan scanners on a limited plan', () => {
    assert.deepEqual(entitledScanners(FREE).sort(), ['docker', 'secret_scanner', 'workflow']);
  });

  it('narrows an "all" request to the entitled set', () => {
    const { scanType, allowedScanTypes } = resolveEntitledScanRequest('all', FREE);
    assert.equal(scanType, 'all');
    assert.deepEqual(allowedScanTypes.sort(), ['docker', 'secret_scanner', 'workflow']);
    assert.ok(!allowedScanTypes.includes('sbom'), 'sbom is not on the free plan');
  });

  it('defaults a missing scan_type to the entitled set', () => {
    const { scanType, allowedScanTypes } = resolveEntitledScanRequest(undefined, FREE);
    assert.equal(scanType, 'all');
    assert.deepEqual(allowedScanTypes.sort(), ['docker', 'secret_scanner', 'workflow']);
  });

  it('allows an explicitly entitled scanner', () => {
    const { scanType, allowedScanTypes } = resolveEntitledScanRequest('docker', FREE);
    assert.equal(scanType, 'docker');
    assert.deepEqual(allowedScanTypes, ['docker']);
  });

  it('rejects a scanner the plan does not include', () => {
    assert.throws(
      () => resolveEntitledScanRequest('sbom', FREE),
      (err) => err.statusCode === 403 && /not included in your plan/i.test(err.message)
    );
  });

  it('rejects an alias spelling of an unentitled scanner', () => {
    assert.equal(normalizeScannerKey('secret-scanner'), 'secret_scanner');
    assert.throws(
      () => resolveEntitledScanRequest('spec_scanner', FREE),
      (err) => err.statusCode === 403
    );
  });

  it('accepts an alias spelling of an entitled scanner', () => {
    const { scanType } = resolveEntitledScanRequest('secret-scanner', FREE);
    assert.equal(scanType, 'secret_scanner');
  });

  it('rejects when the plan entitles no scanners at all', () => {
    assert.throws(
      () => resolveEntitledScanRequest('all', { scanners: [] }),
      (err) => err.statusCode === 403 && /does not include any scanners/i.test(err.message)
    );
  });

  it('rejects an unknown scan_type as a bad request, even on an "all" plan', () => {
    // hasScanner() answers true for any key when the plan holds the `all`
    // wildcard, so the known-scanner check must come first.
    assert.throws(
      () => resolveEntitledScanRequest('made-up-scanner', PRO),
      (err) => err.statusCode === 400 && /Unknown scan type/i.test(err.message)
    );
    assert.throws(
      () => resolveEntitledScanRequest('../../etc/passwd', PRO),
      (err) => err.statusCode === 400
    );
  });
});
