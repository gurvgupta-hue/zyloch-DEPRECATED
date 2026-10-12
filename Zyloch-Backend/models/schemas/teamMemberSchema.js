const mongoose = require('mongoose');

const TeamMemberSchema = new mongoose.Schema(
  {
    tenantId: { type: mongoose.Schema.Types.ObjectId, required: true, index: true },
    installationId: { type: Number, required: true, index: true },
    accountId: { type: Number, required: true, index: true },
    teamId: { type: String, required: true, index: true },
    userId: { type: String, required: true },
    login: { type: String, required: true },
    name: { type: String, default: null },
    email: { type: String, default: null },
    role: { type: String, enum: ['MAINTAINER', 'MEMBER'], default: 'MEMBER' },
    avatarUrl: { type: String, default: null },
  },
  { timestamps: true, collection: 'teammembers' }
);

TeamMemberSchema.index({ installationId: 1, teamId: 1, userId: 1 }, { unique: true });
TeamMemberSchema.index({ installationId: 1, accountId: 1 });
TeamMemberSchema.index({ tenantId: 1, installationId: 1 });

module.exports = { schema: TeamMemberSchema, modelName: 'TeamMember', collection: 'teammembers' };
