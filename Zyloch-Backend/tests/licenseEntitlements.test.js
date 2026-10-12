const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const {
  mergeEntitlements,
  isLicenseActive,
  hasFeature,
  hasScanner,
  hasModule,
  FEATURE_KEYS,
} = require('../services/licenseEntitlements');

describe('licenseEntitlements (plan-tier)', () => {
  const planEntitlements = {
    maxUsers: 10,
    maxRepos: 50,
    maxScansPerMonth: 500,
    scanners: ['docker', 'workflow'],
    modules: ['scanops', 'dashboard'],
    features: {
      'scanops.sbom': false,
      'scanops.workflow': true,
    },
    ssoEnabled: false,
    auditLogRetentionDays: 30,
  };

  it('merges plan defaults with tenant overrides', () => {
    const effective = mergeEntitlements(planEntitlements, {
      features: { 'scanops.sbom': true },
      limits: { maxUsers: 25 },
    });
    assert.equal(effective.maxUsers, 25);
    assert.equal(effective.features['scanops.sbom'], true);
    assert.equal(effective.features['scanops.workflow'], true);
    assert.deepEqual(effective.scanners, ['docker', 'workflow']);
  });

  it('override scanners replaces plan scanner list', () => {
    const effective = mergeEntitlements(planEntitlements, {
      scanners: ['all'],
    });
    assert.deepEqual(effective.scanners, ['all']);
  });

  it('isLicenseActive respects status and expiry', () => {
    assert.equal(isLicenseActive({ status: 'active', expiresAt: null }), true);
    assert.equal(isLicenseActive({ status: 'trialing', expiresAt: null }), true);
    assert.equal(isLicenseActive({ status: 'suspended', expiresAt: null }), false);
    const past = new Date(Date.now() - 86400000);
    assert.equal(isLicenseActive({ status: 'active', expiresAt: past }), false);
  });

  it('hasFeature requires explicit true in features map', () => {
    const ent = mergeEntitlements(planEntitlements, {});
    assert.equal(hasFeature(ent, 'scanops.workflow'), true);
    assert.equal(hasFeature(ent, 'scanops.sbom'), false);
    assert.equal(hasFeature(ent, 'scanops.unknown'), false);
  });

  it('hasScanner supports all wildcard', () => {
    assert.equal(hasScanner({ scanners: ['docker'] }, 'docker'), true);
    assert.equal(hasScanner({ scanners: ['docker'] }, 'sbom'), false);
    assert.equal(hasScanner({ scanners: ['all'] }, 'sbom'), true);
  });

  it('hasModule checks modules list', () => {
    assert.equal(hasModule({ modules: ['scanops'] }, 'scanops'), true);
    assert.equal(hasModule({ modules: ['scanops'] }, 'agent'), false);
    assert.equal(hasModule({ modules: ['all'] }, 'agent'), true);
  });

  it('exports stable feature key constants', () => {
    assert.equal(FEATURE_KEYS.SCANOPS_SBOM, 'scanops.sbom');
  });
});
