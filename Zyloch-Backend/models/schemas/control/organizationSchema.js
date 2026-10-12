const mongoose = require('mongoose');

/**
 * Slim control-plane organization registry. The organization _id is the tenantId
 * and determines the tenant database name. Heavy config (oauth/scans/policies)
 * now lives in the tenant DB's `tenant_settings` document.
 */
const OrganizationSchema = new mongoose.Schema(
  {
    name: { type: String, required: true, trim: true },
    /**
     * Informational only — NOT an identifier.
     *
     * The organization _id is the sole identity of a tenant. Two admins at the
     * same company are two independent tenants that legitimately share a domain,
     * so nothing may key off this field: no uniqueness, no lookup, no adoption.
     * It is recorded purely so a user with several organizations can tell them
     * apart in the switcher.
     */
    domain: { type: String, default: null, lowercase: true, trim: true },
    adminUserId: { type: mongoose.Schema.Types.ObjectId, default: null },
    isActive: { type: Boolean, default: true },
    databaseName: { type: String, required: true, unique: true },
    provisionStatus: {
      type: String,
      enum: ['provisioning', 'active', 'suspended', 'offboarding', 'offboarded'],
      default: 'provisioning',
    },
    indexesVersion: { type: Number, default: 0 },
    provisionedAt: { type: Date, default: null },
  },
  { timestamps: true, collection: 'organizations' }
);

/**
 * Deliberately NOT unique.
 *
 * A domain used to be a claim: the first verified sign-in on it owned the tenant,
 * and everyone else on that domain was pushed into it or locked out. That is wrong
 * — one company can have several unrelated Zyloch organizations, each with its own
 * admin. Tenancy is decided by the organization _id alone.
 *
 * The plain index stays only to keep support/admin queries ("which orgs are on
 * this domain?") from collection-scanning.
 */
OrganizationSchema.index({ domain: 1 });

OrganizationSchema.methods.isAdmin = function isAdmin(userId) {
  if (!this.adminUserId || !userId) return false;
  return this.adminUserId.toString() === userId.toString();
};

module.exports = { schema: OrganizationSchema, modelName: 'Organization', collection: 'organizations' };
