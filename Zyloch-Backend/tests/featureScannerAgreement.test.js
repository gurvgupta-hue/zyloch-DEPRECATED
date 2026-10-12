const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const {
  SCANNER_FEATURE_KEYS,
  scannerEnabled,
  featureDisabled,
  entitledScanners,
  SCANNER_KEYS,
  FEATURE_KEYS,
} = require('../services/licenseEntitlements');
const { isScanOptionLicensed } = require('../controllers/organization');
const { DEFAULT_PLANS } = require('../services/controlBootstrap');

const plan = (planId) => DEFAULT_PLANS.find((p) => p.planId === planId).entitlements;

/**
 * A plan states the same capability twice — once in `scanners`, once in
 * `features`. Only the first was ever enforced, so a feature toggle an admin set
 * in the console did nothing. These cover the gate that now honours both.
 */
describe('A feature toggle qualifies its scanner', () => {
  it('denies a scanner whose governing feature is switched off', () => {
    const entitlements = { scanners: ['sbom'], features: { [FEATURE_KEYS.SCANOPS_SBOM]: false } };
    assert.equal(scannerEnabled(entitlements, 'sbom'), false);
  });

  it('allows a scanner whose governing feature is on', () => {
    const entitlements = { scanners: ['sbom'], features: { [FEATURE_KEYS.SCANOPS_SBOM]: true } };
    assert.equal(scannerEnabled(entitlements, 'sbom'), true);
  });

  it('treats a graded level as on, whatever the depth', () => {
    for (const level of ['basic', 'full']) {
      const entitlements = { scanners: ['docker'], features: { [FEATURE_KEYS.SCANOPS_IAC]: level } };
      assert.equal(scannerEnabled(entitlements, 'docker'), true, `level ${level} should permit`);
    }
  });

  it('does not let a feature grant a scanner the plan never listed', () => {
    const entitlements = { scanners: [], features: { [FEATURE_KEYS.SCANOPS_SBOM]: true } };
    assert.equal(scannerEnabled(entitlements, 'sbom'), false);
  });

  it('leaves a scanner with no governing feature to the allow-list alone', () => {
    assert.equal(SCANNER_FEATURE_KEYS['yaml-json'], undefined);
    assert.equal(scannerEnabled({ scanners: ['yaml-json'], features: {} }, 'yaml-json'), true);
  });

  it('honours the feature even under the "all" wildcard', () => {
    const entitlements = { scanners: ['all'], features: { [FEATURE_KEYS.SCANOPS_YARA]: false } };
    assert.equal(scannerEnabled(entitlements, 'yara'), false);
    assert.equal(scannerEnabled(entitlements, 'sbom'), true, 'unrelated scanners are unaffected');
    assert.ok(!entitledScanners(entitlements).includes('yara'));
  });
});

/**
 * Plans predate the features map. Reading an absent key as "off" would revoke
 * scanners those plans already grant, so silence must stay permissive.
 */
describe('An unstated feature is not a denial', () => {
  it('allows a granted scanner when the plan lists no features at all', () => {
    assert.equal(scannerEnabled({ scanners: ['sbom'] }, 'sbom'), true);
    assert.equal(scannerEnabled({ scanners: ['sbom'], features: {} }, 'sbom'), true);
  });

  it('distinguishes absent from explicitly off', () => {
    assert.equal(featureDisabled({ features: {} }, FEATURE_KEYS.SCANOPS_SBOM), false);
    assert.equal(
      featureDisabled({ features: { [FEATURE_KEYS.SCANOPS_SBOM]: false } }, FEATURE_KEYS.SCANOPS_SBOM),
      true
    );
  });
});

describe('AI-vs-human is gated by its feature, not a phantom scanner', () => {
  it('withholds it from a plan that switches it off, wildcard notwithstanding', () => {
    // Pro holds scanners:['all'] and declares scanops.ai_vs_human false. The old
    // gate asked hasScanner('ai_vs_human') — a key that is not in SCANNER_KEYS —
    // so the wildcard answered yes and Pro got a capability it does not pay for.
    assert.equal(plan('pro').features[FEATURE_KEYS.SCANOPS_AI], false);
    assert.equal(isScanOptionLicensed(plan('pro'), 'ai-vs-human'), false);
  });

  it('grants it to Enterprise, which does pay for it', () => {
    assert.equal(isScanOptionLicensed(plan('enterprise'), 'ai-vs-human'), true);
  });

  it('withholds it from Basic', () => {
    assert.equal(isScanOptionLicensed(plan('basic'), 'ai-vs-human'), false);
  });
});

/**
 * The shipped plans must not contradict themselves: granting a scanner while
 * switching off the feature that governs it silently revokes the scanner, which
 * is how Free nearly lost Docker.
 */
describe('Default plans are internally consistent', () => {
  it('never grants a scanner its own feature flag denies', () => {
    const conflicts = [];
    for (const { planId, entitlements } of DEFAULT_PLANS) {
      for (const [scanner, featureKey] of Object.entries(SCANNER_FEATURE_KEYS)) {
        const listed =
          entitlements.scanners.includes('all') || entitlements.scanners.includes(scanner);
        if (listed && featureDisabled(entitlements, featureKey)) {
          conflicts.push(`${planId}: grants ${scanner} but ${featureKey} is off`);
        }
      }
    }
    assert.deepEqual(conflicts, []);
  });

  it('gives every plan exactly the scanners it lists', () => {
    // The feature gate qualifies the allow-list; it must never quietly shrink it.
    for (const { planId, entitlements } of DEFAULT_PLANS) {
      const listed = entitlements.scanners.includes('all')
        ? [...SCANNER_KEYS]
        : entitlements.scanners;
      assert.deepEqual(
        entitledScanners(entitlements).sort(),
        [...listed].sort(),
        `${planId}: a feature flag is stripping a scanner the plan grants`
      );
    }
  });

  it('gives the top tier every scanner the product ships', () => {
    assert.equal(entitledScanners(plan('enterprise')).length, SCANNER_KEYS.length);
  });
});
