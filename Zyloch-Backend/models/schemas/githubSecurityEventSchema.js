const mongoose = require('mongoose');

const GitHubSecurityEventSchema = new mongoose.Schema(
  {
    tenantId: { type: mongoose.Schema.Types.ObjectId, required: true, index: true },
    installationId: { type: Number, required: true, index: true },
    accountId: { type: Number, required: true, index: true },
    login: { type: String, required: true, index: true },
    source: { type: String, enum: ['webhook', 'audit'], required: true },
    signalType: {
      type: String,
      enum: [
        'pat_request_created',
        'pat_request_approved',
        'pat_request_denied',
        'pat_expired',
        'pat_no_expiry',
        'pat_over_permissive',
        'external_org_fork',
        'team_created',
        'team_deleted',
        'team_member_added',
        'team_member_removed',
        'public_repo_created',
      ],
      required: true,
      index: true,
    },
    severity: { type: String, enum: ['low', 'medium', 'high', 'critical'], default: 'low' },
    action: { type: String, default: null },
    status: { type: String, enum: ['active', 'resolved'], default: 'active' },
    occurredAt: { type: Date, required: true, index: true },
    actor: {
      id: { type: String, default: null },
      login: { type: String, default: null },
    },
    organization: {
      id: { type: Number, default: null },
      login: { type: String, default: null },
    },
    repository: {
      id: { type: Number, default: null },
      name: { type: String, default: null },
      fullName: { type: String, default: null },
      url: { type: String, default: null },
      ownerLogin: { type: String, default: null },
      visibility: { type: String, default: null },
      isPrivate: { type: Boolean, default: null },
    },
    pat: {
      requestId: { type: String, default: null },
      tokenId: { type: String, default: null },
      expiresAt: { type: Date, default: null },
      permissions: { type: mongoose.Schema.Types.Mixed, default: null },
      hasNoExpiry: { type: Boolean, default: false },
      isExpired: { type: Boolean, default: false },
      isOverPermissive: { type: Boolean, default: false },
    },
    metadata: { type: mongoose.Schema.Types.Mixed, default: {} },
    rawPayload: { type: mongoose.Schema.Types.Mixed, default: null },
    dedupeKey: { type: String, required: true, unique: true, index: true },
  },
  { timestamps: true, collection: 'githubsecurityevents' }
);

GitHubSecurityEventSchema.index({ installationId: 1, accountId: 1, signalType: 1, occurredAt: -1 });
GitHubSecurityEventSchema.index({ tenantId: 1, installationId: 1, signalType: 1, occurredAt: -1 });

module.exports = {
  schema: GitHubSecurityEventSchema,
  modelName: 'GitHubSecurityEvent',
  collection: 'githubsecurityevents',
};
