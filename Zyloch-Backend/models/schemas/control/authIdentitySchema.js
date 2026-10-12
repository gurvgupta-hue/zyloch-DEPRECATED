const mongoose = require('mongoose');

/**
 * Login routing table. Maps a global (provider, providerId) identity to the
 * tenant it belongs to, so authentication can resolve the correct tenant DB
 * before loading the user document.
 */
const AuthIdentitySchema = new mongoose.Schema(
  {
    provider: { type: String, enum: ['github', 'google', 'microsoft'], required: true },
    providerId: { type: String, required: true },
    tenantId: { type: mongoose.Schema.Types.ObjectId, required: true, index: true },
    userId: { type: mongoose.Schema.Types.ObjectId, required: true },
    email: { type: String, lowercase: true, trim: true },
  },
  { timestamps: true, collection: 'auth_identities' }
);

// KAN-49: same OAuth identity may belong to multiple tenants (one row per tenant)
AuthIdentitySchema.index({ provider: 1, providerId: 1, tenantId: 1 }, { unique: true });
AuthIdentitySchema.index({ provider: 1, providerId: 1 });
AuthIdentitySchema.index({ email: 1 });

module.exports = { schema: AuthIdentitySchema, modelName: 'AuthIdentity', collection: 'auth_identities' };
