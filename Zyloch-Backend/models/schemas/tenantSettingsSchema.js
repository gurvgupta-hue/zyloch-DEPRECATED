const mongoose = require('mongoose');

/**
 * Single per-tenant configuration document. Consolidates what used to live on
 * the `organization` document (oauthConfigurations, scanConfigurations,
 * policyConfigurations) plus the dropped `policy_configurations` collection.
 */

const OAuthProviderSchema = new mongoose.Schema(
  {
    enabled: { type: Boolean, default: false },
    clientId: { type: String, default: null },
    clientSecret: { type: String, default: null },
    redirectUri: { type: String, default: null },
    configuredAt: { type: Date, default: null },
    configuredBy: { type: mongoose.Schema.Types.ObjectId, default: null },
  },
  { _id: false }
);

const TenantSettingsSchema = new mongoose.Schema(
  {
    // Logical pointer back to the control-plane organization (== tenantId).
    tenantId: { type: mongoose.Schema.Types.ObjectId, required: true, unique: true, index: true },
    oauth: {
      google: { type: OAuthProviderSchema, default: () => ({}) },
      microsoft: { type: OAuthProviderSchema, default: () => ({}) },
    },
    scans: {
      overview: { type: Boolean, default: true },
      workflow: { type: Boolean, default: true },
      docker: { type: Boolean, default: true },
      kubernetes: { type: Boolean, default: true },
      terraform: { type: Boolean, default: true },
      sbom: { type: Boolean, default: true },
      'yaml-json': { type: Boolean, default: true },
      'secret-scanner': { type: Boolean, default: true },
      yara: { type: Boolean, default: true },
      'ai-vs-human': { type: Boolean, default: true },
      iac: { type: Boolean, default: true },
      // Both are rendered as toggles (Scan Options / sidebar) and are gate keys
      // in GHAPP's SCAN_CONFIG_MAP; without a field here the toggle silently
      // failed to persist. Default true keeps existing tenants unchanged.
      'spec-scanner': { type: Boolean, default: true },
      'skill-scanner': { type: Boolean, default: true },
    },
    automation: {
      /**
       * Scan every repository's default branch when an installation summary
       * sync finishes.
       *
       * Opt-in, and off by default: a sync is how a tenant refreshes its
       * installation data, and having that silently fan out a full scan across
       * every repo burns plan quota and looks indistinguishable from a runaway
       * trigger. Tenants that want baseline coverage after a sync turn it on.
       */
      autoScanOnSync: { type: Boolean, default: false },
    },
    // Free-form map: { scanners: { <scanner_key>: { enabled, policies: {} } } }
    policies: { type: mongoose.Schema.Types.Mixed, default: {} },
  },
  { timestamps: true, collection: 'tenant_settings' }
);

module.exports = {
  schema: TenantSettingsSchema,
  modelName: 'TenantSettings',
  collection: 'tenant_settings',
};
