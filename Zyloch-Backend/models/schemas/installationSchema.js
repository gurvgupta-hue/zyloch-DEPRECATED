const mongoose = require('mongoose');

/**
 * GitHub App installation, scoped to the tenant DB it lives in.
 * The org link (`zylochOrganizationId`) is no longer needed because the
 * containing database *is* the tenant. Webhook routing from installationId
 * to tenant is handled by the control-plane `installation_index` collection.
 */
const InstallationSchema = new mongoose.Schema(
  {
    installationId: { type: Number, required: true },
    account: {
      id: { type: Number, required: true },
      login: { type: String, required: true },
      type: { type: String, required: true },
    },
    // `repos` holds at most the tenant plan's `maxRepos` entries (see
    // services/licenseLimits.js). `repoCount` is what the installation actually
    // has on GitHub, so a plan breach stays visible after the list is capped.
    repos: { type: [String], default: [] },
    repositorySelection: { type: String, enum: ['all', 'selected'], default: 'selected' },
    repoCount: { type: Number, default: 0 },
    repoLimit: { type: Number, default: null },
    reposTruncated: { type: Boolean, default: false },
    // The repositories the tenant chose to monitor when the installation holds
    // more than the plan allows. Empty means "no choice needed / not made yet";
    // `repoSelection.completedAt` is what says a choice has been recorded, so an
    // admin who deliberately selects nothing is not read as "never asked".
    selectedRepos: { type: [String], default: [] },
    repoSelection: {
      completedAt: { type: Date, default: null },
      completedBy: { type: String, default: null },
      source: { type: String, enum: ['manual', 'auto', null], default: null },
      limitAtSelection: { type: Number, default: null },
    },
    installer: {
      id: { type: Number },
      login: { type: String },
      avatarUrl: { type: String },
      profileUrl: { type: String },
    },
    linkedBy: {
      userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
      userEmail: { type: String },
      linkedAt: { type: Date, default: Date.now },
    },
    lastFetchedAt: { type: Date, default: null },
  },
  { timestamps: true }
);

InstallationSchema.index({ installationId: 1 }, { unique: true });

module.exports = { schema: InstallationSchema, modelName: 'Installation', collection: 'installations' };
