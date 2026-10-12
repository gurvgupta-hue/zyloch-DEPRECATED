const mongoose = require('mongoose');
const { EntitlementOverridesSchema } = require('./entitlementsSchema');

const TenantLicenseSchema = new mongoose.Schema(
  {
    tenantId: { type: mongoose.Schema.Types.ObjectId, required: true, unique: true },
    planId: { type: String, required: true },
    status: {
      type: String,
      enum: ['active', 'trialing', 'suspended', 'cancelled'],
      default: 'active',
    },
    startsAt: { type: Date, default: Date.now },
    expiresAt: { type: Date, default: null },
    /** Per-tenant overrides on plan entitlements (features, limits, scanners). */
    overrides: { type: EntitlementOverridesSchema, default: () => ({}) },
  },
  { timestamps: true, collection: 'tenant_licenses' }
);

module.exports = {
  schema: TenantLicenseSchema,
  modelName: 'TenantLicense',
  collection: 'tenant_licenses',
};
