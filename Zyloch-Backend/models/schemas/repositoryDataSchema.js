const mongoose = require('mongoose');

const BranchSchema = new mongoose.Schema(
  {
    name: { type: String, required: true },
    target: {
      oid: String,
      committedDate: Date,
      message: String,
      author: { name: String, email: String },
    },
    isDefault: { type: Boolean, default: false },
  },
  { _id: false }
);

const RepositoryDataSchema = new mongoose.Schema(
  {
    tenantId: { type: mongoose.Schema.Types.ObjectId, required: true, index: true },
    installationId: { type: Number, required: true, index: true },
    accountId: { type: Number, required: true, index: true },
    login: { type: String, required: true, index: true },
    repositoryName: { type: String, required: true },
    repositoryUrl: { type: String, required: true },
    owner: { type: String, required: true },
    isPrivate: { type: Boolean, default: false },
    isArchived: { type: Boolean, default: false },
    isInternal: { type: Boolean, default: false },
    stars: { type: Number, default: 0 },
    forks: { type: Number, default: 0 },
    branches: [BranchSchema],
    staleBranchCount: { type: Number, default: 0 },
    totalCommits: { type: Number, default: 0 },
    lastActive: { type: Date },
  },
  { timestamps: true, collection: 'repositorydata' }
);

RepositoryDataSchema.index(
  { installationId: 1, login: 1, repositoryName: 1 },
  { unique: true }
);
RepositoryDataSchema.index({ tenantId: 1, installationId: 1 });

module.exports = {
  schema: RepositoryDataSchema,
  modelName: 'RepositoryData',
  collection: 'repositorydata',
};
