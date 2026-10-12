const mongoose = require('mongoose');

/**
 * Pending member invites for a tenant (tenant DB).
 * Accept flow: invitee signs in with Google/Microsoft using orgId; admin invite
 * reserves capacity at create time via assertUserCapacity.
 */
const MemberInviteSchema = new mongoose.Schema(
  {
    tenantId: { type: mongoose.Schema.Types.ObjectId, required: true, index: true },
    email: { type: String, required: true, lowercase: true, trim: true, index: true },
    invitedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    status: {
      type: String,
      enum: ['pending', 'accepted', 'revoked', 'expired'],
      default: 'pending',
      index: true,
    },
    token: { type: String, required: true, unique: true },
    expiresAt: { type: Date, required: true },
    acceptedAt: { type: Date, default: null },
    acceptedUserId: { type: mongoose.Schema.Types.ObjectId, default: null },
  },
  { timestamps: true, collection: 'member_invites' }
);

MemberInviteSchema.index({ tenantId: 1, email: 1, status: 1 });

module.exports = {
  schema: MemberInviteSchema,
  modelName: 'MemberInvite',
  collection: 'member_invites',
};
