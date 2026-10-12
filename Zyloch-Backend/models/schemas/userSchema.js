const mongoose = require('mongoose');

/**
 * Identity sub-document — a single linked auth method (github/google/microsoft).
 * Lives inside a tenant's `users` collection; no org scoping needed since the
 * whole collection already belongs to one tenant DB.
 */
const IdentitySchema = new mongoose.Schema(
  {
    provider: { type: String, enum: ['github', 'google', 'microsoft'], required: true },
    providerId: { type: String, required: true },
    providerData: {
      login: String,
      email: String,
      name: String,
      avatar_url: String,
      accountType: String,
    },
    accessToken: { type: String },
    refreshToken: { type: String },
    tokenExpiry: { type: Date },
    lastUsedAt: { type: Date, default: Date.now },
    createdAt: { type: Date, default: Date.now },
  },
  { _id: true }
);

const UserSchema = new mongoose.Schema(
  {
    email: { type: String, required: true, lowercase: true, trim: true, index: true },
    name: { type: String },
    avatar_url: { type: String },
    accountType: { type: String, enum: ['User', 'Organization'], default: 'User' },
    login: { type: String },
    githubId: { type: Number, sparse: true },
    identities: [IdentitySchema],
    primaryIdentity: {
      provider: { type: String, enum: ['github', 'google', 'microsoft'] },
      providerId: String,
    },
    role: { type: String, enum: ['admin', 'member'], default: 'member' },
    preferences: {
      theme: {
        type: String,
        enum: ['light', 'dark', 'teal-modern', 'teal-modern-dark'],
        default: 'light',
      },
      timeZone: { type: String, enum: ['UTC', 'IST', 'EST', 'PST', 'CET'], default: 'UTC' },
    },
    isActive: { type: Boolean, default: true },
    lastLoginAt: { type: Date, default: Date.now },
  },
  { timestamps: true }
);

// Within a tenant DB an identity maps to exactly one user.
UserSchema.index(
  { 'identities.provider': 1, 'identities.providerId': 1 },
  { unique: true, sparse: true, name: 'unique_identity_per_tenant' }
);

UserSchema.methods.getIdentity = function getIdentity(provider) {
  return this.identities.find((id) => id.provider === provider);
};

UserSchema.methods.hasIdentity = function hasIdentity(provider) {
  return this.identities.some((id) => id.provider === provider);
};

UserSchema.methods.getLinkedProviders = function getLinkedProviders() {
  return this.identities.map((id) => id.provider);
};

UserSchema.methods.unlinkIdentity = async function unlinkIdentity(provider) {
  if (this.identities.length <= 1) {
    throw new Error('Cannot unlink the only authentication method');
  }
  this.identities = this.identities.filter((id) => id.provider !== provider);
  if (this.primaryIdentity.provider === provider) {
    this.primaryIdentity = {
      provider: this.identities[0].provider,
      providerId: this.identities[0].providerId,
    };
  }
  await this.save();
  return this;
};

UserSchema.methods.updateIdentityTokens = async function updateIdentityTokens(provider, tokens) {
  const identity = this.identities.find((id) => id.provider === provider);
  if (!identity) {
    throw new Error(`Identity not found for provider: ${provider}`);
  }
  identity.accessToken = tokens.accessToken;
  if (tokens.refreshToken) identity.refreshToken = tokens.refreshToken;
  identity.tokenExpiry = tokens.tokenExpiry;
  identity.lastUsedAt = new Date();
  await this.save();
  return this;
};

module.exports = { schema: UserSchema, modelName: 'User', collection: 'users' };
