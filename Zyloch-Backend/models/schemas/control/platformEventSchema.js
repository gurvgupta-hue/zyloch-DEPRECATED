const mongoose = require('mongoose');

/**
 * Append-only audit / lifecycle log. Replaces the dropped `backupinstallations`
 * collection: an installation removal is recorded as a `installation.removed`
 * event with the prior installation snapshot embedded in `payload.snapshot`.
 */
const PlatformEventSchema = new mongoose.Schema(
  {
    tenantId: { type: mongoose.Schema.Types.ObjectId, default: null, index: true },
    eventType: { type: String, required: true, index: true },
    actorUserId: { type: mongoose.Schema.Types.ObjectId, default: null },
    payload: { type: mongoose.Schema.Types.Mixed, default: {} },
    occurredAt: { type: Date, default: Date.now },
  },
  { timestamps: { createdAt: true, updatedAt: false }, collection: 'platform_events' }
);

module.exports = {
  schema: PlatformEventSchema,
  modelName: 'PlatformEvent',
  collection: 'platform_events',
};
