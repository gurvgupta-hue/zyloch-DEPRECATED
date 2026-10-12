const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const {
  SCAN_ID_TO_LICENSE_SCANNER_KEYS,
  SCAN_ID_TO_LICENSE_FEATURE_KEY,
  isScanOptionLicensed,
} = require('../controllers/organization');
const {
  SCANNER_KEYS,
  scannerEnabled,
  entitledScanners,
} = require('../services/licenseEntitlements');
const { resolveEntitledScanRequest } = require('../controllers/scans');
const { DEFAULT_PLANS } = require('../services/controlBootstrap');

const BASIC = 'basic';

const planEntitlements = (planId) =>
  DEFAULT_PLANS.find((p) => p.planId === planId).entitlements;

/** True when the trigger endpoint would actually run this scan type. */
function canTrigger(scanType, entitlements) {
  try {
    resolveEntitledScanRequest(scanType, entitlements);
    return true;
  } catch {
    return false;
  }
}

/**
 * These assert the *shape* of tiering rather than a particular price list, so a
 * packaging change updates the seed and not this file. What must never change
 * is that tiers differ, and that nobody is shown a control that then 403s.
 */
describe('Tiering actually separates the plans', () => {
  const paidOnly = SCANNER_KEYS.filter(
    (key) =>
      !scannerEnabled(planEntitlements(BASIC), key) &&
      scannerEnabled(planEntitlements('enterprise'), key)
  );

  it('withholds something from the entry tier', () => {
    assert.ok(paidOnly.length > 0, 'every scanner is in the entry tier — tiering is meaningless');
  });

  it('refuses a scanner the entry tier does not include', () => {
    for (const scanner of paidOnly) {
      let err;
      try {
        resolveEntitledScanRequest(scanner, planEntitlements(BASIC));
      } catch (e) {
        err = e;
      }
      assert.equal(err?.statusCode, 403, `${scanner} should be refused on the entry tier`);
      assert.match(err.message, /not included in your plan/i);
    }
  });

  it('runs every scanner a plan does include', () => {
    for (const { planId, entitlements } of DEFAULT_PLANS) {
      for (const scanner of entitledScanners(entitlements)) {
        assert.ok(
          canTrigger(scanner, entitlements),
          `${planId} grants ${scanner} but the trigger endpoint refuses it`
        );
      }
    }
  });

  it('never lets a group request pull in a scanner the plan lacks', () => {
    // Asking for `iac` must narrow to the members this plan holds, not hand over
    // the whole group.
    for (const { planId, entitlements } of DEFAULT_PLANS) {
      if (!canTrigger('iac', entitlements)) continue;
      const { allowedScanTypes } = resolveEntitledScanRequest('iac', entitlements);
      for (const scanner of allowedScanTypes) {
        assert.ok(
          scannerEnabled(entitlements, scanner),
          `${planId} would run ${scanner} via the iac group without being entitled to it`
        );
      }
    }
  });
});

/**
 * The bug this guards: a Scan Options card rendered for a tenant whose trigger
 * request will then be refused. The two gates live in different controllers, so
 * they are checked against each other rather than against a fixed list.
 */
describe('What is offered matches what will run', () => {
  it('licenses a scan option exactly when its scan can be triggered', () => {
    for (const { planId, entitlements } of DEFAULT_PLANS) {
      for (const scanId of Object.keys(SCAN_ID_TO_LICENSE_SCANNER_KEYS)) {
        assert.equal(
          isScanOptionLicensed(entitlements, scanId),
          canTrigger(scanId, entitlements),
          `${planId}: "${scanId}" is offered and refused, or withheld and runnable`
        );
      }
    }
  });

  it('gates a feature-only option on its feature', () => {
    // ai-vs-human is not a runnable scanner, so it has no trigger path to agree
    // with — the feature is the only authority.
    for (const { planId, entitlements } of DEFAULT_PLANS) {
      const granted = entitlements.features?.['scanops.ai_vs_human'];
      assert.equal(
        isScanOptionLicensed(entitlements, 'ai-vs-human'),
        granted === true || typeof granted === 'string',
        `${planId}: ai-vs-human visibility disagrees with its feature flag`
      );
    }
  });

  it('only maps scanner keys that actually exist', () => {
    const unknown = Object.entries(SCAN_ID_TO_LICENSE_SCANNER_KEYS)
      .flatMap(([, keys]) => keys)
      .filter((k) => !SCANNER_KEYS.includes(k));
    assert.deepEqual(unknown, [], `mapped to non-existent scanners: ${unknown.join(', ')}`);
  });

  it('maps every scanner-backed scan option (drift guard)', () => {
    // These are the ids rendered by ScanOptionsCard / the scanops sidebar. An id
    // here with no mapping is shown to every tenant regardless of plan.
    const UI_SCAN_IDS = [
      'workflow',
      'iac',
      'sbom',
      'yaml-json',
      'secret-scanner',
      'yara',
      'ai-vs-human',
      'skill-scanner',
    ];
    const unmapped = UI_SCAN_IDS.filter(
      (id) => !SCAN_ID_TO_LICENSE_SCANNER_KEYS[id] && !SCAN_ID_TO_LICENSE_FEATURE_KEY[id]
    );
    assert.deepEqual(
      unmapped,
      [],
      `scan options with no license mapping (shown to every plan): ${unmapped.join(', ')}`
    );
  });
});
