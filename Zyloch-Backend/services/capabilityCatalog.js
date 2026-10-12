/**
 * Capability catalog — the single source of truth for everything a license plan
 * can grant.
 *
 * Why this exists: plan authoring used to mean hand-writing an `entitlements`
 * blob and remembering every scanner and feature key. Anything forgotten was
 * silently ungranted, and a typo was indistinguishable from "not included".
 *
 * The definition lives in `config/capabilityCatalog.seed.json` rather than in
 * this file because the platform console can edit the catalog too, and those
 * edits are exported back into that file so a fresh cluster seeds the shape
 * admins actually chose rather than a stale hardcoded default. Adding a scanner
 * to SCANNER_KEYS without listing it in the seed fails a test, so the console
 * can never drift behind the product.
 *
 * The split of responsibility with the console matters, because it is what makes
 * the boot-time publish non-destructive: this file is the only thing that knows
 * which scanner and feature *keys* exist (that is a claim about code existing),
 * while labels, help text, grouping, ordering and limit defaults are decided by
 * a human in the console. `publishCapabilityCatalog` reconciles the former and
 * never overwrites the latter.
 *
 * Grouping is presentation only. Groups exist so the console can show
 * "IaC Scanner" instead of seven raw keys; enforcement always happens on the
 * individual scanner keys.
 */

const SEED = require('../config/capabilityCatalog.seed.json');

const {
  SCANNER_KEYS,
  SCANNER_FEATURE_KEYS,
  FEATURE_LEVELS,
  UNLIMITED,
  normalizeLevel,
} = require('./licenseEntitlements');

const CATALOG_VERSION = SEED.version;

/** Numeric limits a plan can set. */
const LIMIT_DEFINITIONS = Object.freeze(SEED.limits.map((l) => Object.freeze({ ...l })));

/**
 * Scanner groups. Every key in SCANNER_KEYS must appear in exactly one group —
 * enforced by test, so a new scanner cannot be invisible to plan authoring.
 */
const SCANNER_GROUPS = Object.freeze(
  SEED.scannerGroups.map((g) => Object.freeze({ ...g, scanners: Object.freeze([...g.scanners]) }))
);

/**
 * Product features. `levels` present == graded capability (rendered as a select);
 * null == on/off (rendered as a checkbox).
 */
const FEATURE_DEFINITIONS = Object.freeze(
  SEED.features.map((f) =>
    Object.freeze({ ...f, levels: f.levels ? Object.freeze([...f.levels]) : null })
  )
);

/** Flat list of every scanner key referenced by a group. */
function catalogScannerKeys() {
  return SCANNER_GROUPS.flatMap((group) => group.scanners);
}

/** Flat list of every feature key in the catalog. */
function catalogFeatureKeys() {
  return FEATURE_DEFINITIONS.map((f) => f.key);
}

/**
 * The serialisable catalog, as stored in the control DB and read by the console.
 */
function buildCatalog() {
  return {
    version: CATALOG_VERSION,
    unlimitedValue: UNLIMITED,
    featureLevels: FEATURE_LEVELS,
    // Published so the console can tell which feature qualifies which scanner
    // without keeping its own copy of the mapping — it is what decides whether a
    // listed scanner will actually run.
    scannerFeatureKeys: SCANNER_FEATURE_KEYS,
    limits: LIMIT_DEFINITIONS.map((l) => ({ ...l })),
    scannerGroups: SCANNER_GROUPS.map((g) => ({ ...g, scanners: [...g.scanners] })),
    features: FEATURE_DEFINITIONS.map((f) => ({ ...f, levels: f.levels ? [...f.levels] : null })),
    updatedAt: new Date(),
  };
}

/**
 * Reconcile the stored catalog with what this build ships.
 *
 * This is what stops the boot-time publish from wiping console edits. The two
 * sides write disjoint things: this build is the only thing that knows which
 * scanner and feature *keys* exist, and a human in the console decides labels,
 * help text, grouping, ordering and limit defaults. So a normal boot adds keys
 * the product gained, drops keys it lost, and touches nothing else.
 *
 * `version` is the escape hatch for a deliberate product reshape (renaming a
 * group, collapsing a level scale) that genuinely must overwrite presentation.
 * Bumping the seed's version past the stored one applies the seed wholesale,
 * once; every boot after that is a key-only merge again. The console must never
 * bump `version` for this reason — it bumps `revision` instead.
 *
 * @param {object|null} stored the catalog document currently in the control DB
 * @param {object} fresh what this build ships, from `buildCatalog()`
 */
function mergeCatalog(stored, fresh = buildCatalog()) {
  if (!stored) return fresh;

  const storedVersion = Number(stored.version) || 0;
  const reshaped = Number(fresh.version) > storedVersion;
  if (reshaped) {
    return { ...stored, ...fresh, revision: stored.revision || 0, updatedAt: new Date() };
  }

  const shipped = new Set(SCANNER_KEYS);
  const groups = (stored.scannerGroups || [])
    .map((group) => ({
      ...group,
      scanners: (group.scanners || []).filter((key) => shipped.has(key)),
    }))
    .filter((group) => group.scanners.length > 0);

  const placed = new Set(groups.flatMap((group) => group.scanners));
  for (const group of fresh.scannerGroups) {
    const missing = group.scanners.filter((key) => !placed.has(key));
    if (!missing.length) continue;
    // Only place a scanner the console has not already filed somewhere; its
    // choice of group wins over the seed's.
    const target = groups.find((g) => g.id === group.id);
    if (target) target.scanners.push(...missing);
    else groups.push({ ...group, scanners: missing });
  }

  const merged = (storedList = [], freshList = [], idOf) => {
    const shippedNow = new Map(freshList.map((item) => [idOf(item), item]));
    const kept = storedList.filter((item) => shippedNow.has(idOf(item)));
    const present = new Set(kept.map(idOf));
    return kept.concat(freshList.filter((item) => !present.has(idOf(item))));
  };

  return {
    ...stored,
    version: storedVersion,
    unlimitedValue: fresh.unlimitedValue,
    featureLevels: fresh.featureLevels,
    scannerFeatureKeys: fresh.scannerFeatureKeys,
    scannerGroups: groups,
    features: merged(stored.features, fresh.features, (f) => f.key),
    limits: merged(stored.limits, fresh.limits, (l) => l.key),
    updatedAt: new Date(),
  };
}

/**
 * Validate an authored entitlements blob against the catalog.
 *
 * Catches the two failure modes hand-authoring had: a key that does not exist
 * (typo, or a scanner that was renamed) and a graded feature set to a level that
 * is not on the ladder at all.
 *
 * A level that is on the ladder but no longer offered by the feature is *not* a
 * problem: the catalog's level scale is editable, so a live plan can name a
 * level a later edit removed. Those resolve through `normalizeLevel` instead of
 * failing, so a cosmetic catalog change cannot invalidate existing plans.
 *
 * @returns {string[]} problems; empty when the entitlements are valid
 */
function validateEntitlements(entitlements = {}) {
  const problems = [];
  const knownScanners = new Set(SCANNER_KEYS);
  const knownFeatures = new Map(FEATURE_DEFINITIONS.map((f) => [f.key, f]));
  const knownLimits = new Set(LIMIT_DEFINITIONS.map((l) => l.key));

  for (const scanner of entitlements.scanners || []) {
    if (scanner === 'all') continue;
    if (!knownScanners.has(scanner)) {
      problems.push(`Unknown scanner: "${scanner}"`);
    }
  }

  for (const [key, value] of Object.entries(entitlements.features || {})) {
    const definition = knownFeatures.get(key);
    if (!definition) {
      problems.push(`Unknown feature: "${key}"`);
      continue;
    }
    if (typeof value === 'boolean' || value == null) continue;

    const level = String(value).trim().toLowerCase();
    if (!FEATURE_LEVELS[level]) {
      problems.push(`Feature "${key}" has an unknown level: "${value}"`);
    } else if (!definition.levels) {
      problems.push(`Feature "${key}" is on/off and cannot take level "${level}"`);
    }
  }

  for (const [key, value] of Object.entries(entitlements.limitPolicy || {})) {
    if (!knownLimits.has(key)) {
      problems.push(`Unknown limit in limitPolicy: "${key}"`);
      continue;
    }
    const mode = String(value).trim().toLowerCase();
    if (!['hard', 'soft'].includes(mode)) {
      problems.push(`limitPolicy."${key}" must be "hard" or "soft", got "${value}"`);
    }
    const definition = LIMIT_DEFINITIONS.find((l) => l.key === key);
    if (mode === 'soft' && definition && !definition.supportsSoftLimit) {
      problems.push(`Limit "${key}" does not support a soft mode`);
    }
  }

  for (const key of knownLimits) {
    const value = entitlements[key];
    if (value == null) continue;
    if (!Number.isFinite(Number(value))) {
      problems.push(`Limit "${key}" must be a number (use ${UNLIMITED} for unlimited)`);
    }
  }

  return problems;
}

/**
 * Resolve a plan's graded features onto the levels the catalog currently offers.
 *
 * The console renders a select per graded feature; without this a plan authored
 * before a level scale changed would render as "no selection" and an admin
 * saving the form would silently downgrade the tenant.
 */
function resolveFeatureLevels(entitlements = {}) {
  const resolved = {};
  for (const definition of FEATURE_DEFINITIONS) {
    const value = (entitlements.features || {})[definition.key];
    if (value == null || typeof value === 'boolean' || !definition.levels) continue;
    resolved[definition.key] = normalizeLevel(value, definition.levels);
  }
  return resolved;
}

/**
 * Capabilities present in the product but not granted (or denied) by a plan.
 *
 * The console shows these so an author can see what they have not decided on,
 * rather than a missing key silently meaning "off".
 */
function findUnsetCapabilities(entitlements = {}) {
  const scanners = new Set(entitlements.scanners || []);
  const grantsAll = scanners.has('all');
  const features = entitlements.features || {};

  return {
    scanners: grantsAll ? [] : SCANNER_KEYS.filter((key) => !scanners.has(key)),
    features: catalogFeatureKeys().filter(
      (key) => !Object.prototype.hasOwnProperty.call(features, key)
    ),
  };
}

module.exports = {
  CATALOG_VERSION,
  LIMIT_DEFINITIONS,
  SCANNER_GROUPS,
  FEATURE_DEFINITIONS,
  buildCatalog,
  mergeCatalog,
  catalogScannerKeys,
  catalogFeatureKeys,
  validateEntitlements,
  resolveFeatureLevels,
  findUnsetCapabilities,
};
