const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const {
  SCANNER_GROUPS,
  FEATURE_DEFINITIONS,
  LIMIT_DEFINITIONS,
  buildCatalog,
  mergeCatalog,
  catalogScannerKeys,
  catalogFeatureKeys,
  validateEntitlements,
  resolveFeatureLevels,
  findUnsetCapabilities,
} = require('../services/capabilityCatalog');
const {
  SCANNER_KEYS,
  FEATURE_KEYS,
  FEATURE_LEVELS,
  UNLIMITED,
} = require('../services/licenseEntitlements');

/**
 * These are the invariants that make "nothing gets missed" true. If someone
 * ships a scanner or a feature and does not list it here, plan authoring would
 * silently be unable to grant it — so that failure is a failing test, not a
 * support ticket six weeks later.
 */
describe('Catalog completeness', () => {
  it('lists every scanner the product ships', () => {
    const missing = SCANNER_KEYS.filter((key) => !catalogScannerKeys().includes(key));
    assert.deepEqual(
      missing,
      [],
      `scanners missing from SCANNER_GROUPS (plan authoring cannot grant them): ${missing.join(', ')}`
    );
  });

  it('does not reference a scanner that does not exist', () => {
    const unknown = catalogScannerKeys().filter((key) => !SCANNER_KEYS.includes(key));
    assert.deepEqual(unknown, [], `catalog references unknown scanners: ${unknown.join(', ')}`);
  });

  it('puts each scanner in exactly one group', () => {
    const seen = new Map();
    for (const group of SCANNER_GROUPS) {
      for (const key of group.scanners) {
        seen.set(key, (seen.get(key) || []).concat(group.id));
      }
    }
    const duplicated = [...seen.entries()].filter(([, groups]) => groups.length > 1);
    assert.deepEqual(
      duplicated.map(([key, groups]) => `${key} in ${groups.join(' + ')}`),
      [],
      'a scanner in two groups makes a group toggle ambiguous'
    );
  });

  it('lists every canonical feature key', () => {
    const missing = Object.values(FEATURE_KEYS).filter(
      (key) => !catalogFeatureKeys().includes(key)
    );
    assert.deepEqual(missing, [], `FEATURE_KEYS missing from the catalog: ${missing.join(', ')}`);
  });

  it('uses unique ids and keys throughout', () => {
    const groupIds = SCANNER_GROUPS.map((g) => g.id);
    assert.equal(new Set(groupIds).size, groupIds.length, 'duplicate scanner group id');
    const featureKeys = catalogFeatureKeys();
    assert.equal(new Set(featureKeys).size, featureKeys.length, 'duplicate feature key');
    const limitKeys = LIMIT_DEFINITIONS.map((l) => l.key);
    assert.equal(new Set(limitKeys).size, limitKeys.length, 'duplicate limit key');
  });

  it('only uses levels that exist on the ladder', () => {
    for (const feature of FEATURE_DEFINITIONS) {
      for (const level of feature.levels || []) {
        assert.ok(FEATURE_LEVELS[level], `feature ${feature.key} uses unknown level "${level}"`);
      }
    }
  });

  it('gives every capability a human label', () => {
    for (const item of [...SCANNER_GROUPS, ...FEATURE_DEFINITIONS, ...LIMIT_DEFINITIONS]) {
      assert.ok(item.label && item.label.trim().length > 0, `missing label on ${item.id || item.key}`);
    }
  });
});

describe('Catalog serialisation', () => {
  it('is JSON-safe for the console to read from Mongo', () => {
    const catalog = buildCatalog();
    assert.doesNotThrow(() => JSON.stringify(catalog));
    assert.equal(catalog.unlimitedValue, UNLIMITED);
    assert.ok(catalog.version >= 1);
    assert.ok(catalog.scannerGroups.length > 0);
    assert.ok(catalog.features.length > 0);
    assert.ok(catalog.limits.length > 0);
  });

  it('marks graded features with their levels and on/off features with null', () => {
    const catalog = buildCatalog();
    const graded = catalog.features.find((f) => f.key === FEATURE_KEYS.SCANOPS_IAC);
    const boolean = catalog.features.find((f) => f.key === FEATURE_KEYS.SCANOPS_SBOM);
    assert.deepEqual(graded.levels, ['basic', 'full']);
    assert.equal(boolean.levels, null);
  });
});

describe('Entitlement validation against the catalog', () => {
  it('accepts a well-formed plan', () => {
    assert.deepEqual(
      validateEntitlements({
        maxUsers: UNLIMITED,
        maxRepos: 5000,
        maxScansPerDay: 600,
        limitPolicy: { maxScansPerDay: 'soft' },
        scanners: ['sbom', 'secret_scanner', 'docker'],
        features: { [FEATURE_KEYS.SCANOPS_IAC]: 'limited', [FEATURE_KEYS.SCANOPS_SBOM]: true },
      }),
      []
    );
  });

  it('accepts the "all" scanner wildcard', () => {
    assert.deepEqual(validateEntitlements({ scanners: ['all'] }), []);
  });

  it('rejects a typo in a scanner key', () => {
    const problems = validateEntitlements({ scanners: ['secret-scaner'] });
    assert.equal(problems.length, 1);
    assert.match(problems[0], /Unknown scanner/);
  });

  it('rejects an unknown feature key', () => {
    const problems = validateEntitlements({ features: { 'scanops.telepathy': true } });
    assert.match(problems[0], /Unknown feature/);
  });

  it('rejects a level that is not on the ladder at all', () => {
    const problems = validateEntitlements({
      features: { [FEATURE_KEYS.SCANOPS_IAC]: 'platinum' },
    });
    assert.match(problems[0], /unknown level/);
  });

  it('accepts a ladder level the feature no longer offers', () => {
    // A live plan may name a level a later catalog edit removed; invalidating it
    // would mean a cosmetic edit breaks plan authoring.
    assert.deepEqual(
      validateEntitlements({ features: { [FEATURE_KEYS.SCANOPS_IAC]: 'advanced' } }),
      []
    );
  });

  it('rejects a level on an on/off feature', () => {
    const problems = validateEntitlements({
      features: { [FEATURE_KEYS.SCANOPS_SBOM]: 'basic' },
    });
    assert.match(problems[0], /on\/off and cannot take level/);
  });

  it('rejects a bad limit policy', () => {
    assert.match(validateEntitlements({ limitPolicy: { maxScansPerDay: 'maybe' } })[0], /must be/);
    assert.match(validateEntitlements({ limitPolicy: { maxWidgets: 'soft' } })[0], /Unknown limit/);
  });

  it('rejects a soft mode on a limit that does not support it', () => {
    const problems = validateEntitlements({ limitPolicy: { maxUsers: 'soft' } });
    assert.match(problems[0], /does not support a soft mode/);
  });

  it('rejects a non-numeric limit', () => {
    assert.match(validateEntitlements({ maxRepos: 'lots' })[0], /must be a number/);
  });
});

/**
 * The publish step runs on every process boot, not every deploy. If it
 * overwrote the stored document, a console edit would survive only until the
 * next restart — so these are the invariants that make console editing viable
 * at all.
 */
describe('Catalog merge on boot', () => {
  /** A stored document as the console would leave it after an admin edit. */
  function storedAfterConsoleEdit() {
    const catalog = buildCatalog();
    return {
      ...catalog,
      revision: 3,
      scannerGroups: catalog.scannerGroups.map((g) =>
        g.id === 'yara' ? { ...g, label: 'Malware rules (renamed by admin)' } : g
      ),
      limits: catalog.limits.map((l) =>
        l.key === 'maxRepos' ? { ...l, label: 'Repos (renamed by admin)' } : l
      ),
    };
  }

  it('seeds the full catalog when nothing is stored yet', () => {
    const fresh = buildCatalog();
    assert.deepEqual(mergeCatalog(null, fresh), fresh);
  });

  it('preserves console labels across a boot', () => {
    const merged = mergeCatalog(storedAfterConsoleEdit(), buildCatalog());
    assert.equal(
      merged.scannerGroups.find((g) => g.id === 'yara').label,
      'Malware rules (renamed by admin)'
    );
    assert.equal(
      merged.limits.find((l) => l.key === 'maxRepos').label,
      'Repos (renamed by admin)'
    );
  });

  it('is idempotent, so repeated restarts do not drift', () => {
    const stored = storedAfterConsoleEdit();
    const once = mergeCatalog(stored, buildCatalog());
    const twice = mergeCatalog(once, buildCatalog());
    assert.deepEqual(
      { ...twice, updatedAt: null },
      { ...once, updatedAt: null },
      'a second boot changed the document'
    );
  });

  it('keeps a scanner in the group the console moved it to', () => {
    const stored = storedAfterConsoleEdit();
    // Admin moves yaml-json out of code-quality and into the yara group.
    stored.scannerGroups = stored.scannerGroups.map((g) => {
      if (g.id === 'code-quality') return { ...g, scanners: [] };
      if (g.id === 'yara') return { ...g, scanners: [...g.scanners, 'yaml-json'] };
      return g;
    });

    const merged = mergeCatalog(stored, buildCatalog());
    const holders = merged.scannerGroups.filter((g) => g.scanners.includes('yaml-json'));
    assert.deepEqual(holders.map((g) => g.id), ['yara'], 'the seed re-added a moved scanner');
  });

  it('adds a newly shipped scanner and feature', () => {
    const stored = storedAfterConsoleEdit();
    stored.scannerGroups = stored.scannerGroups.filter((g) => g.id !== 'cis-agent');
    stored.features = stored.features.filter((f) => f.key !== FEATURE_KEYS.SCANOPS_CIS_AGENT);

    const merged = mergeCatalog(stored, buildCatalog());
    assert.ok(
      merged.scannerGroups.some((g) => g.scanners.includes('cis-agent')),
      'a scanner shipped after the last console edit never reached plan authoring'
    );
    assert.ok(merged.features.some((f) => f.key === FEATURE_KEYS.SCANOPS_CIS_AGENT));
  });

  it('drops a capability the product no longer ships', () => {
    const stored = storedAfterConsoleEdit();
    stored.scannerGroups = [
      ...stored.scannerGroups,
      { id: 'retired', label: 'Retired', scanners: ['telepathy-scanner'] },
    ];
    stored.features = [...stored.features, { key: 'scanops.telepathy', label: 'Telepathy' }];

    const merged = mergeCatalog(stored, buildCatalog());
    assert.ok(!merged.scannerGroups.some((g) => g.id === 'retired'));
    assert.ok(!merged.features.some((f) => f.key === 'scanops.telepathy'));
  });

  it('applies a deliberate reshape when the seed version is newer', () => {
    const stored = { ...storedAfterConsoleEdit(), version: 1 };
    const fresh = { ...buildCatalog(), version: 99 };

    const merged = mergeCatalog(stored, fresh);
    assert.equal(merged.version, 99);
    assert.equal(
      merged.scannerGroups.find((g) => g.id === 'yara').label,
      'YARA Scanner',
      'a version bump must be able to correct presentation'
    );
    assert.equal(merged.revision, 3, 'the console revision counter survives a reshape');
  });

  it('never rolls the version backwards', () => {
    const stored = { ...storedAfterConsoleEdit(), version: 50 };
    assert.equal(mergeCatalog(stored, { ...buildCatalog(), version: 2 }).version, 50);
  });
});

describe('Seed export round-trip', () => {
  it('exports a freshly seeded catalog back to a byte-identical seed file', () => {
    // Without this, the first `catalog:export` after any deploy produces a
    // spurious diff and stops signalling "an admin actually changed something".
    const fs = require('fs');
    const { toSeed, SEED_PATH } = require('../scripts/export-capability-catalog');

    assert.equal(
      `${JSON.stringify(toSeed(buildCatalog()), null, 2)}\n`,
      fs.readFileSync(SEED_PATH, 'utf8')
    );
  });
});

describe('Level resolution against an edited scale', () => {
  it('snaps a level the feature no longer offers onto one it does', () => {
    // 'advanced' outranks 'full', so it resolves to the best offered level.
    assert.equal(
      resolveFeatureLevels({ features: { [FEATURE_KEYS.SCANOPS_IAC]: 'advanced' } })[
        FEATURE_KEYS.SCANOPS_IAC
      ],
      'full'
    );
    // 'limited' ranks below 'basic', so it floors to the lowest offered level.
    assert.equal(
      resolveFeatureLevels({ features: { [FEATURE_KEYS.SCANOPS_IAC]: 'limited' } })[
        FEATURE_KEYS.SCANOPS_IAC
      ],
      'basic'
    );
  });

  it('leaves an offered level untouched', () => {
    assert.equal(
      resolveFeatureLevels({ features: { [FEATURE_KEYS.SCANOPS_IAC]: 'basic' } })[
        FEATURE_KEYS.SCANOPS_IAC
      ],
      'basic'
    );
  });

  it('ignores booleans and on/off features', () => {
    const resolved = resolveFeatureLevels({
      features: { [FEATURE_KEYS.SCANOPS_IAC]: true, [FEATURE_KEYS.SCANOPS_SBOM]: true },
    });
    assert.deepEqual(resolved, {});
  });
});

describe('Unset capability reporting', () => {
  it('reports what a plan has not decided on', () => {
    const unset = findUnsetCapabilities({
      scanners: ['sbom'],
      features: { [FEATURE_KEYS.SCANOPS_SBOM]: true },
    });
    assert.ok(unset.scanners.includes('secret_scanner'));
    assert.ok(!unset.scanners.includes('sbom'));
    assert.ok(unset.features.includes(FEATURE_KEYS.SCANOPS_IAC));
    assert.ok(!unset.features.includes(FEATURE_KEYS.SCANOPS_SBOM));
  });

  it('treats an explicit false as decided, not unset', () => {
    const unset = findUnsetCapabilities({ features: { [FEATURE_KEYS.SCANOPS_SBOM]: false } });
    assert.ok(!unset.features.includes(FEATURE_KEYS.SCANOPS_SBOM));
  });

  it('reports nothing unset when a plan grants all scanners', () => {
    assert.deepEqual(findUnsetCapabilities({ scanners: ['all'] }).scanners, []);
  });
});
