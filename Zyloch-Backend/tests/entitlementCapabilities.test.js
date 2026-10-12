const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const {
  UNLIMITED,
  isUnlimited,
  presentLimit,
  featureRank,
  featureLevel,
  hasFeature,
  hasFeatureAtLeast,
  limitMode,
  mergeEntitlements,
  FEATURE_LEVELS,
} = require('../services/licenseEntitlements');
const {
  readLimit,
  evaluateLimit,
  capReposToLimit,
  LIMIT_KEYS,
} = require('../services/licenseLimits');

describe('Unlimited limits (per-seat / Enterprise plans)', () => {
  it('distinguishes "none allowed" from "no ceiling"', () => {
    assert.equal(readLimit({ maxUsers: 0 }, 'maxUsers'), 0);
    assert.equal(readLimit({ maxUsers: UNLIMITED }, 'maxUsers'), Number.POSITIVE_INFINITY);
    assert.equal(isUnlimited(UNLIMITED), true);
    assert.equal(isUnlimited(0), false);
  });

  it('treats absent or malformed limits as none, not unlimited', () => {
    assert.equal(readLimit({}, 'maxUsers'), 0);
    assert.equal(readLimit({ maxUsers: 'abc' }, 'maxUsers'), 0);
    assert.equal(readLimit(null, 'maxUsers'), 0);
  });

  it('never reports an uncapped limit as exceeded', () => {
    const verdict = evaluateLimit(LIMIT_KEYS.MAX_USERS, {
      current: 10_000,
      limit: readLimit({ maxUsers: UNLIMITED }, 'maxUsers'),
      entitlements: {},
    });
    assert.equal(verdict.exceeded, false);
  });

  it('still enforces a real cap', () => {
    const verdict = evaluateLimit(LIMIT_KEYS.MAX_USERS, {
      current: 3,
      limit: readLimit({ maxUsers: 3 }, 'maxUsers'),
      entitlements: {},
    });
    assert.equal(verdict.exceeded, true);
  });

  it('serialises unlimited as null for API responses', () => {
    assert.equal(presentLimit(UNLIMITED), null);
    assert.equal(presentLimit(Number.POSITIVE_INFINITY), null);
    assert.equal(presentLimit(50), 50);
    assert.equal(presentLimit(0), 0);
  });

  it('does not truncate a repo list on an uncapped plan', () => {
    const repos = Array.from({ length: 5000 }, (_, i) => `repo-${i}`);
    assert.equal(capReposToLimit(repos, Number.POSITIVE_INFINITY).length, 5000);
    assert.equal(capReposToLimit(repos, 50).length, 50);
    assert.equal(capReposToLimit(repos, 0).length, 0);
  });
});

describe('Graded feature levels', () => {
  const plan = {
    features: {
      'scanops.secret_scanner': 'basic',
      'scanops.iac': 'limited',
      'scanops.sbom': true,
      'scanops.spec_scanner': false,
      'ai.insights': 'advanced',
    },
  };

  it('maps booleans onto the ladder', () => {
    assert.equal(featureRank(plan, 'scanops.sbom'), FEATURE_LEVELS.full);
    assert.equal(featureRank(plan, 'scanops.spec_scanner'), 0);
  });

  it('reads graded levels', () => {
    assert.equal(featureLevel(plan, 'scanops.secret_scanner'), 'basic');
    assert.equal(featureLevel(plan, 'scanops.iac'), 'limited');
    assert.equal(featureLevel(plan, 'ai.insights'), 'advanced');
  });

  it('treats any level as entitled', () => {
    // "Limited IaC" is still IaC — this is what a boolean field could not express.
    assert.equal(hasFeature(plan, 'scanops.iac'), true);
    assert.equal(hasFeature(plan, 'scanops.spec_scanner'), false);
    assert.equal(hasFeature(plan, 'never.listed'), false);
  });

  it('gates capability that needs a higher grade', () => {
    assert.equal(hasFeatureAtLeast(plan, 'scanops.secret_scanner', 'basic'), true);
    assert.equal(hasFeatureAtLeast(plan, 'scanops.secret_scanner', 'full'), false);
    assert.equal(hasFeatureAtLeast(plan, 'scanops.sbom', 'full'), true);
    assert.equal(hasFeatureAtLeast(plan, 'ai.insights', 'enhanced'), true);
  });

  it('is case and whitespace tolerant, and rejects nonsense levels', () => {
    assert.equal(featureRank({ features: { x: '  FULL ' } }, 'x'), FEATURE_LEVELS.full);
    assert.equal(featureRank({ features: { x: 'platinum' } }, 'x'), 0);
    assert.equal(hasFeatureAtLeast(plan, 'scanops.sbom', 'platinum'), false);
  });

  it('unlisted features stay opt-in', () => {
    assert.equal(featureLevel({ features: {} }, 'anything'), null);
    assert.equal(featureRank(null, 'anything'), 0);
  });
});

describe('Soft limits and overages', () => {
  it('defaults every limit to hard', () => {
    assert.equal(limitMode({}, 'maxScansPerDay'), 'hard');
    assert.equal(limitMode({ limitPolicy: {} }, 'maxScansPerDay'), 'hard');
  });

  it('reads a soft policy per limit key', () => {
    const ent = { limitPolicy: { maxScansPerDay: 'soft' } };
    assert.equal(limitMode(ent, 'maxScansPerDay'), 'soft');
    assert.equal(limitMode(ent, 'maxScansPerMonth'), 'hard', 'soft must not leak across limits');
  });

  it('reports mode alongside the breach so callers can allow-and-bill', () => {
    const soft = evaluateLimit(LIMIT_KEYS.MAX_SCANS_PER_DAY, {
      current: 600,
      limit: 600,
      entitlements: { limitPolicy: { maxScansPerDay: 'soft' } },
    });
    assert.equal(soft.exceeded, true);
    assert.equal(soft.mode, 'soft');
  });
});

describe('mergeEntitlements carries the new fields', () => {
  it('defaults the daily limit to unlimited when a plan omits it', () => {
    const merged = mergeEntitlements({ maxScansPerMonth: 50 }, {});
    assert.equal(merged.maxScansPerDay, UNLIMITED);
    assert.equal(readLimit(merged, 'maxScansPerDay'), Number.POSITIVE_INFINITY);
  });

  it('takes the plan daily limit and merges the policy', () => {
    const merged = mergeEntitlements(
      { maxScansPerDay: 600, limitPolicy: { maxScansPerDay: 'soft' } },
      {}
    );
    assert.equal(merged.maxScansPerDay, 600);
    assert.equal(limitMode(merged, 'maxScansPerDay'), 'soft');
  });

  it('lets a tenant override win, including an explicit 0', () => {
    const merged = mergeEntitlements(
      { maxUsers: 3, maxScansPerDay: 150 },
      { limits: { maxUsers: 0, maxScansPerDay: UNLIMITED } }
    );
    assert.equal(merged.maxUsers, 0);
    assert.equal(merged.maxScansPerDay, UNLIMITED);
  });

  it('lets an override change the enforcement mode', () => {
    const merged = mergeEntitlements(
      { maxScansPerDay: 600, limitPolicy: { maxScansPerDay: 'hard' } },
      { limitPolicy: { maxScansPerDay: 'soft' } }
    );
    assert.equal(limitMode(merged, 'maxScansPerDay'), 'soft');
  });

  it('merges graded feature overrides over plan defaults', () => {
    const merged = mergeEntitlements(
      { features: { 'scanops.secret_scanner': 'basic' } },
      { features: { 'scanops.secret_scanner': 'full' } }
    );
    assert.equal(featureLevel(merged, 'scanops.secret_scanner'), 'full');
  });
});
