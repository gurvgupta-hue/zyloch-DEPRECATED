const mongoose = require('mongoose');

const jobSchema = new mongoose.Schema(
  {
    tenantId: { type: mongoose.Schema.Types.ObjectId, required: true, index: true },
    installationId: { type: Number, required: true },
    login: { type: String, required: true },
    accountId: { type: Number, required: true },
    accountType: { type: String, enum: ['Organization', 'User'], default: 'User' },
    status: {
      type: String,
      enum: ['pending', 'in_progress', 'completed', 'failed'],
      default: 'pending',
    },
    progress: { type: Number, default: 0 },
    summary: {
      totals: {
        totalRepositories: Number,
        totalBranches: Number,
        totalCommits: Number,
        totalForks: Number,
        totalStars: Number,
        totalPrivate: Number,
        totalPublic: Number,
        totalInternal: Number,
        totalBytes: Number,
        totalArchivedRepos: Number,
        totalStaleBranches: Number,
        totalTeams: Number,
        totalTeamMembers: Number,
        totalSecurityEvents: Number,
        totalPatNoExpiry: Number,
        totalPatExpired: Number,
        totalPatOverPermissive: Number,
        totalExternalForks: Number,
      },
      languages: [
        { name: String, bytes: Number, repo_count: Number, percentage: Number, color: String },
      ],
      repositories: [
        {
          name: String,
          url: String,
          stars: Number,
          forks: Number,
          isPrivate: Boolean,
          branches: Number,
          commits: Number,
          lastCommit: Date,
          lastActive: Date,
        },
      ],
      teams: [
        {
          teamId: String,
          teamName: String,
          teamSlug: String,
          memberCount: Number,
          repositoriesCount: Number,
        },
      ],
    },
    error: String,
    bullmqJobId: { type: String, default: null },
    lastWorkerStart: Date,
  },
  { timestamps: true, collection: 'installation_summary_jobs' }
);

jobSchema.index({ installationId: 1, login: 1 }, { unique: true });
jobSchema.index({ tenantId: 1, installationId: 1 });

module.exports = {
  schema: jobSchema,
  modelName: 'InstallationSummaryJob',
  collection: 'installation_summary_jobs',
};
