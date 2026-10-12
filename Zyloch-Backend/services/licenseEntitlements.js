/**
 * Plan-tier entitlement resolver (Strategy 1).
 *
 * Effective access = license_plans.entitlements merged with tenant_licenses.overrides.
 * Deny if license status is not active/trialing or plan is missing.
 */

const { getControlModels } = require('../db/controlModels');

const ACTIVE_STATUSES = new Set(['active', 'trialing']);

/**
 * Sentinel for an uncapped numeric limit.
 *
 * `0` means "none allowed"; `-1` means "no ceiling". Keeping them distinct is
 * what lets a per-seat or Enterprise plan be uncapped without reading as a plan
 * with zero seats.
 */
const UNLIMITED = -1;

function isUnlimited(value) {
  return Number(value) < 0;
}

/**
 * Present a resolved limit for an API response. Infinity is not valid JSON, so
 * an uncapped limit is surfaced as `null` and clients render it as "unlimited".
 */
function presentLimit(value) {
  const n = Number(value);
  if (!Number.isFinite(n)) return null; // Infinity / NaN
  return isUnlimited(n) ? null : n;
}

/**
 * Ordered capability ladder for graded features (MT pricing model).
 *
 * A plan may grant a feature at a level rather than a boolean — e.g. a Basic
 * Secret Scanner on one tier and a Full one on the next. Booleans still work:
 * `true` reads as 'full', `false` as none. `0` is reserved for "not entitled".
 */
const FEATURE_LEVELS = Object.freeze({
  limited: 1,
  basic: 2,
  standard: 3,
  full: 4,
  enhanced: 5,
  advanced: 6,
});

/** Canonical feature keys used across BE / FE gating. */
const FEATURE_KEYS = Object.freeze({
  SCANOPS_SBOM: 'scanops.sbom',
  SCANOPS_SPEC: 'scanops.spec_scanner',
  SCANOPS_IAC: 'scanops.iac',
  SCANOPS_SECRET: 'scanops.secret_scanner',
  SCANOPS_WORKFLOW: 'scanops.workflow',
  SCANOPS_YARA: 'scanops.yara',
  SCANOPS_AI: 'scanops.ai_vs_human',
  SCANOPS_SKILL_SCANNER: 'scanops.skill_scanner',
  SCANOPS_CIS_AGENT: 'scanops.cis_agent',
  SETTINGS_SSO: 'settings.sso',
  SETTINGS_OAUTH_GOOGLE: 'settings.oauth_google',
  SETTINGS_OAUTH_MICROSOFT: 'settings.oauth_microsoft',
});

/**
 * Canonical scanner keys. Mirrors SUPPORTED_SCANNERS in the GHAPP service
 * (Zyloch-GHAPP-Backend/config/tenant_db.py) — keep the two in step.
 */
const SCANNER_KEYS = Object.freeze([
  'docker',
  'kubernetes',
  'workflow',
  'yaml-json',
  'secret_scanner',
  'yara',
  'terraform_azure',
  'terraform_gcp',
  'terraform_aws',
  'sbom',
  'spec-scanner',
  'bicep',
  'ansible',
  // Scanners main added after entitlements were written. They must be listed or
  // resolveEntitledScanRequest() rejects them as "Unknown scan type" and the
  // feature is unreachable through the tenant-guarded BFF.
  'cloudformation',
  'skill-scanner',
  'cis-agent',
]);

/** Frontend spellings that differ from the canonical scanner key. */
const SCANNER_ALIASES = Object.freeze({
  'secret-scanner': 'secret_scanner',
  'spec_scanner': 'spec-scanner',
  'yaml_json': 'yaml-json',
  'skill_scanner': 'skill-scanner',
  'cis_agent': 'cis-agent',
  'cfn': 'cloudformation',
});

/**
 * Scan-request groups: values a caller may send that mean "several scanners".
 *
 * These are NOT scanner keys — a plan grants the members, never the group — but
 * they are valid `scan_type` values because GHAPP expands them itself (see
 * `_IAC_SCANNERS` / `_TERRAFORM_SCANNERS` in Zyloch-GHAPP-Backend/main.py).
 * Keep the two lists in step.
 *
 * Without this a request for `iac` was rejected as an unknown scan type, because
 * the entitlement check only recognised individual scanners.
 */
const SCANNER_REQUEST_GROUPS = Object.freeze({
  iac: Object.freeze([
    'docker',
    'kubernetes',
    'terraform_aws',
    'terraform_azure',
    'terraform_gcp',
    'bicep',
    'ansible',
    'cloudformation',
  ]),
  terraform: Object.freeze(['terraform_aws', 'terraform_azure', 'terraform_gcp']),
});

/** Members of a scan-request group, or null when `scanType` is not a group. */
function expandScannerGroup(scanType) {
  const raw = String(scanType || '').trim().toLowerCase();
  const members = SCANNER_REQUEST_GROUPS[raw];
  return members ? [...members] : null;
}

/** Normalize a requested scan type to a canonical scanner key. */
function normalizeScannerKey(scanType) {
  const raw = String(scanType || '').trim();
  if (!raw) return null;
  return SCANNER_ALIASES[raw] || raw;
}

function plainObject(value) {
  if (!value) return {};
  if (value instanceof Map) return Object.fromEntries(value);
  if (typeof value.toObject === 'function') return value.toObject();
  return { ...value };
}

function mergeEntitlements(planEntitlements = {}, overrides = {}) {
  const plan = plainObject(planEntitlements);
  const ovr = plainObject(overrides);
  const planFeatures = plainObject(plan.features);
  const overrideFeatures = plainObject(ovr.features);
  const planLimits = {
    maxUsers: plan.maxUsers,
    maxRepos: plan.maxRepos,
    maxScansPerMonth: plan.maxScansPerMonth,
    maxScansPerDay: plan.maxScansPerDay,
  };
  const overrideLimits = plainObject(ovr.limits);
  // `null` is the "no override" marker in the overrides schema, so `??` is the
  // right operator here — an explicit override of 0 must still win.
  const pickLimit = (key, fallback = 0) =>
    overrideLimits[key] ?? planLimits[key] ?? fallback;

  const effective = {
    maxUsers: pickLimit('maxUsers'),
    maxRepos: pickLimit('maxRepos'),
    maxScansPerMonth: pickLimit('maxScansPerMonth'),
    // Defaults to unlimited: a plan with only a monthly ceiling must not be
    // silently capped at zero scans per day.
    maxScansPerDay: pickLimit('maxScansPerDay', UNLIMITED),
    limitPolicy: { ...plainObject(plan.limitPolicy), ...plainObject(ovr.limitPolicy) },
    scanners: ovr.scanners ?? plan.scanners ?? [],
    features: { ...planFeatures, ...overrideFeatures },
    modules: plan.modules ?? ['scanops', 'dashboard'],
    ssoEnabled: ovr.ssoEnabled ?? plan.ssoEnabled ?? false,
    auditLogRetentionDays: plan.auditLogRetentionDays ?? 30,
  };

  return effective;
}

/**
 * Enforcement mode for a limit: 'soft' lets the request through and records an
 * overage; anything else (the default) rejects at the ceiling.
 */
function limitMode(entitlements, limitKey) {
  const policy = plainObject(entitlements?.limitPolicy);
  return String(policy[limitKey] || 'hard').toLowerCase() === 'soft' ? 'soft' : 'hard';
}

function isLicenseActive(license) {
  if (!license) return false;
  if (!ACTIVE_STATUSES.has(license.status)) return false;
  if (license.expiresAt && new Date(license.expiresAt) < new Date()) return false;
  return true;
}

/**
 * Resolve a feature to a rank on the FEATURE_LEVELS ladder.
 * @returns {number} 0 when the feature is not entitled at all.
 */
function featureRank(entitlements, featureKey) {
  if (!entitlements || !featureKey) return 0;
  const value = plainObject(entitlements.features)[featureKey];

  if (value === true) return FEATURE_LEVELS.full;
  if (value === false || value == null) return 0; // unlisted = explicit opt-in per plan

  if (typeof value === 'string') {
    return FEATURE_LEVELS[value.trim().toLowerCase()] || 0;
  }
  // A raw number is accepted so a plan can be authored against the ladder directly.
  const numeric = Number(value);
  return Number.isFinite(numeric) && numeric > 0 ? numeric : 0;
}

/**
 * Snap a level onto the scale a feature actually offers.
 *
 * The catalog's level scale is editable, so a plan authored against an older
 * scale can name a level the feature no longer offers (a plan granting 'limited'
 * IaC outlives the collapse to basic/full). Rejecting those would invalidate
 * live plans on a purely cosmetic catalog edit, so a stale level resolves to the
 * best offered level it still earns: the highest one at or below its rank, or
 * the lowest offered level when it outranks nothing.
 *
 * @returns {string|null} an offered level, or null when `value` is not on the ladder
 */
function normalizeLevel(value, offeredLevels) {
  const level = String(value || '').trim().toLowerCase();
  const rank = FEATURE_LEVELS[level];
  if (!rank) return null;
  if (!offeredLevels?.length || offeredLevels.includes(level)) return level;

  const ranked = offeredLevels
    .map((name) => ({ name, rank: FEATURE_LEVELS[name] }))
    .filter((entry) => entry.rank)
    .sort((a, b) => a.rank - b.rank);
  if (!ranked.length) return null;

  const affordable = ranked.filter((entry) => entry.rank <= rank);
  return affordable.length ? affordable[affordable.length - 1].name : ranked[0].name;
}

/**
 * The level a plan grants for a feature.
 * @returns {string|null} e.g. 'basic', 'full'; null when not entitled.
 */
function featureLevel(entitlements, featureKey) {
  const rank = featureRank(entitlements, featureKey);
  if (rank <= 0) return null;
  const match = Object.entries(FEATURE_LEVELS).find(([, value]) => value === rank);
  return match ? match[0] : null;
}

/** True when the feature is entitled at any level. */
function hasFeature(entitlements, featureKey) {
  return featureRank(entitlements, featureKey) > 0;
}

/**
 * True when the feature is entitled at `minimumLevel` or better.
 * Use this to gate capability that only the higher grade includes — e.g.
 * custom secret patterns needing 'full' rather than 'basic'.
 */
function hasFeatureAtLeast(entitlements, featureKey, minimumLevel) {
  const required =
    typeof minimumLevel === 'number'
      ? minimumLevel
      : FEATURE_LEVELS[String(minimumLevel || '').trim().toLowerCase()];
  if (!required) return false;
  return featureRank(entitlements, featureKey) >= required;
}

function hasScanner(entitlements, scannerKey) {
  if (!entitlements || !scannerKey) return false;
  const scanners = entitlements.scanners || [];
  if (scanners.includes('all')) return true;
  return scanners.includes(scannerKey);
}

/**
 * The feature key governing each scanner, where the catalog defines one.
 *
 * A plan describes the same capability twice: `scanners` is the per-scanner
 * allow-list the trigger path enforces, and `features` is the coarser map the
 * pricing sheet is written in. They must agree, or a plan says one thing and the
 * product does another — Pro declaring `scanops.ai_vs_human: false` while the
 * `all` wildcard let it through is exactly that bug.
 *
 * `yaml-json` is absent deliberately: the catalog ships no feature for it, so the
 * scanner list alone governs it.
 */
const SCANNER_FEATURE_KEYS = Object.freeze({
  sbom: 'scanops.sbom',
  secret_scanner: 'scanops.secret_scanner',
  workflow: 'scanops.workflow',
  'spec-scanner': 'scanops.spec_scanner',
  yara: 'scanops.yara',
  'skill-scanner': 'scanops.skill_scanner',
  'cis-agent': 'scanops.cis_agent',
  docker: 'scanops.iac',
  kubernetes: 'scanops.iac',
  terraform_aws: 'scanops.iac',
  terraform_azure: 'scanops.iac',
  terraform_gcp: 'scanops.iac',
  bicep: 'scanops.iac',
  ansible: 'scanops.iac',
  cloudformation: 'scanops.iac',
});

/**
 * True only when a plan explicitly switches a feature off.
 *
 * Deliberately not the same as `!hasFeature`, which also reports an *absent* key
 * as off. Use this wherever a feature qualifies capability a plan already grants
 * by another route (a scanner in the allow-list, an OAuth provider already
 * configured): plans predate the features map, so reading silence as a denial
 * would revoke access those plans currently have. Only a stated `false`
 * overrides. Where a feature is the sole authority, use `hasFeature` instead.
 */
function featureDisabled(entitlements, featureKey) {
  const features = plainObject(entitlements?.features);
  if (!Object.prototype.hasOwnProperty.call(features, featureKey)) return false;
  return !hasFeature(entitlements, featureKey);
}

/**
 * True when a plan lists the scanner and has not switched off the feature
 * governing it. The gate for "may this tenant run this scanner".
 */
function scannerEnabled(entitlements, scannerKey) {
  if (!hasScanner(entitlements, scannerKey)) return false;
  const featureKey = SCANNER_FEATURE_KEYS[scannerKey];
  return !featureKey || !featureDisabled(entitlements, featureKey);
}

/**
 * Expand a tenant's `scanners` entitlement into concrete scanner keys.
 *
 * Used when a caller asks for `scan_type: "all"` — "all" must mean "all scanners
 * this plan includes", not "every scanner the platform ships" (MT-05.2).
 *
 * @returns {string[]} canonical scanner keys, empty when nothing is entitled
 */
function entitledScanners(entitlements) {
  return SCANNER_KEYS.filter((key) => scannerEnabled(entitlements, key));
}

function hasModule(entitlements, moduleKey) {
  if (!entitlements || !moduleKey) return false;
  const modules = entitlements.modules || [];
  return modules.includes('all') || modules.includes(moduleKey);
}

/**
 * Resolve effective entitlements for a tenant.
 * @returns {Promise<{
 *   tenantId: string,
 *   planId: string|null,
 *   status: string,
 *   active: boolean,
 *   entitlements: object,
 *   plan: object|null,
 * }>}
 */
async function resolveTenantEntitlements(tenantId) {
  const { TenantLicense, LicensePlan } = getControlModels();
  const license = await TenantLicense.findOne({ tenantId }).lean();
  const tenantIdStr = String(tenantId);

  if (!license) {
    return {
      tenantId: tenantIdStr,
      planId: null,
      status: 'missing',
      active: false,
      entitlements: mergeEntitlements({}, {}),
      plan: null,
    };
  }

  const plan = await LicensePlan.findOne({ planId: license.planId, isActive: true }).lean();
  const active = isLicenseActive(license) && !!plan;
  const entitlements = mergeEntitlements(plan?.entitlements, license.overrides);

  return {
    tenantId: tenantIdStr,
    planId: license.planId,
    status: license.status,
    active,
    entitlements,
    plan: plan
      ? { planId: plan.planId, name: plan.name, description: plan.description }
      : null,
  };
}

/** Assert tenant has an active license; throws Error with code ENTITLEMENT_DENIED. */
async function assertActiveLicense(tenantId) {
  const resolved = await resolveTenantEntitlements(tenantId);
  if (!resolved.active) {
    const err = new Error('Tenant license is not active or plan is unavailable');
    err.code = 'ENTITLEMENT_DENIED';
    err.status = 403;
    throw err;
  }
  return resolved;
}

/** Assert a feature key is enabled for the tenant. */
async function assertFeature(tenantId, featureKey) {
  const resolved = await assertActiveLicense(tenantId);
  if (!hasFeature(resolved.entitlements, featureKey)) {
    const err = new Error(`Feature not included in plan: ${featureKey}`);
    err.code = 'FEATURE_NOT_ENTITLED';
    err.status = 403;
    throw err;
  }
  return resolved;
}

module.exports = {
  FEATURE_KEYS,
  FEATURE_LEVELS,
  SCANNER_KEYS,
  SCANNER_ALIASES,
  SCANNER_FEATURE_KEYS,
  scannerEnabled,
  featureDisabled,
  SCANNER_REQUEST_GROUPS,
  expandScannerGroup,
  ACTIVE_STATUSES,
  UNLIMITED,
  isUnlimited,
  presentLimit,
  featureRank,
  featureLevel,
  normalizeLevel,
  hasFeatureAtLeast,
  limitMode,
  normalizeScannerKey,
  entitledScanners,
  mergeEntitlements,
  isLicenseActive,
  hasFeature,
  hasScanner,
  hasModule,
  resolveTenantEntitlements,
  assertActiveLicense,
  assertFeature,
};
