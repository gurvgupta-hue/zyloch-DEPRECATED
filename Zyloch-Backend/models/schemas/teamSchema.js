const mongoose = require('mongoose');

const TeamSchema = new mongoose.Schema(
  {
    tenantId: { type: mongoose.Schema.Types.ObjectId, required: true, index: true },
    installationId: { type: Number, required: true, index: true },
    accountId: { type: Number, required: true, index: true },
    login: { type: String, required: true, index: true },
    teamId: { type: String, required: true },
    teamName: { type: String, required: true },
    teamSlug: { type: String, required: true },
    description: { type: String, default: null },
    privacy: { type: String, enum: ['SECRET', 'CLOSED', 'VISIBLE'], default: 'SECRET' },
    memberCount: { type: Number, default: 0 },
    repositoriesCount: { type: Number, default: 0 },
  },
  { timestamps: true, collection: 'teams' }
);

TeamSchema.index({ installationId: 1, accountId: 1, teamId: 1 }, { unique: true });
TeamSchema.index({ installationId: 1, login: 1 });
TeamSchema.index({ tenantId: 1, installationId: 1 });

module.exports = { schema: TeamSchema, modelName: 'Team', collection: 'teams' };
