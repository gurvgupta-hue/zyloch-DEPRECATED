const mongoose = require('mongoose');

/**
 * Webhook routing table. Maps a GitHub installation id to the owning tenant so
 * incoming webhook events can be written into the correct tenant DB.
 */
const InstallationIndexSchema = new mongoose.Schema(
  {
    githubInstallationId: { type: Number, required: true, unique: true },
    tenantId: { type: mongoose.Schema.Types.ObjectId, required: true, index: true },
    accountLogin: { type: String },
    accountType: { type: String },
    linkedAt: { type: Date, default: Date.now },
  },
  { timestamps: { createdAt: false, updatedAt: true }, collection: 'installation_index' }
);

module.exports = {
  schema: InstallationIndexSchema,
  modelName: 'InstallationIndex',
  collection: 'installation_index',
};
