const mongoose = require('mongoose');

/**
 * Shared shape for plan defaults and merged effective entitlements.
 *
 * Numeric limits use `-1` to mean UNLIMITED (see UNLIMITED in
 * services/licenseEntitlements.js). `0` means "none allowed" — the two are
 * deliberately different, so an Enterprise plan can be uncapped without
 * accidentally reading as "no seats".
 */
const EntitlementsSchema = new mongoose.Schema(
  {
    maxUsers: { type: Number, default: 0 },
    maxRepos: { type: Number, default: 0 },
    maxScansPerMonth: { type: Number, default: 0 },
    /**
     * Daily scan ceiling. Plans priced per day (e.g. 150/day, 600/day) enforce
     * here; leave at -1 for plans that only have a monthly ceiling.
     */
    maxScansPerDay: { type: Number, default: -1 },
    /**
     * Per-limit enforcement mode: 'hard' (default) rejects at the ceiling,
     * 'soft' allows the request through and records an overage for billing.
     * Keyed by limit name, e.g. `{ maxScansPerDay: 'soft' }`.
     */
    limitPolicy: { type: mongoose.Schema.Types.Mixed, default: {} },
    scanners: { type: [String], default: [] },
    /**
     * Product feature keys, e.g. scanops.sbom, settings.sso.
     *
     * Values are either a boolean (`true` == full access, `false` == none) or a
     * graded level string — 'limited' | 'basic' | 'standard' | 'full' |
     * 'enhanced' | 'advanced' — so a plan can ship, say, a Basic Secret Scanner
     * and a Full one on a higher tier. See FEATURE_LEVELS in
     * services/licenseEntitlements.js.
     */
    features: { type: mongoose.Schema.Types.Mixed, default: {} },
    /** High-level modules included in the plan */
    modules: { type: [String], default: ['scanops', 'dashboard'] },
    ssoEnabled: { type: Boolean, default: false },
    auditLogRetentionDays: { type: Number, default: 30 },
  },
  { _id: false }
);

/** Per-tenant overrides layered on top of the plan (plan-tier model). */
const EntitlementOverridesSchema = new mongoose.Schema(
  {
    features: { type: mongoose.Schema.Types.Mixed, default: {} },
    limits: {
      maxUsers: { type: Number, default: null },
      maxRepos: { type: Number, default: null },
      maxScansPerMonth: { type: Number, default: null },
      maxScansPerDay: { type: Number, default: null },
    },
    limitPolicy: { type: mongoose.Schema.Types.Mixed, default: undefined },
    scanners: { type: [String], default: undefined },
    ssoEnabled: { type: Boolean, default: null },
  },
  { _id: false }
);

module.exports = { EntitlementsSchema, EntitlementOverridesSchema };
