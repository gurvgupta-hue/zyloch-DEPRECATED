/**
 * Tenant model registry.
 *
 * Binds the tenant schemas to a per-tenant connection handle (shared cluster
 * pool, see connectionManager). Models are compiled lazily and cached on the
 * connection handle by Mongoose, so repeated calls are cheap.
 */

const { getTenantDb } = require('./connectionManager');

const userSchema = require('../models/schemas/userSchema');
const installationSchema = require('../models/schemas/installationSchema');
const repositoryDataSchema = require('../models/schemas/repositoryDataSchema');
const teamSchema = require('../models/schemas/teamSchema');
const teamMemberSchema = require('../models/schemas/teamMemberSchema');
const githubSecurityEventSchema = require('../models/schemas/githubSecurityEventSchema');
const installationSummaryJobSchema = require('../models/schemas/installationSummaryJobSchema');
const tenantSettingsSchema = require('../models/schemas/tenantSettingsSchema');
const memberInviteSchema = require('../models/schemas/memberInviteSchema');

const TENANT_SCHEMAS = [
  userSchema,
  installationSchema,
  repositoryDataSchema,
  teamSchema,
  teamMemberSchema,
  githubSecurityEventSchema,
  installationSummaryJobSchema,
  tenantSettingsSchema,
  memberInviteSchema,
];

function bindModel(conn, { modelName, schema, collection }) {
  // Reuse the already-compiled model for this connection if present.
  if (conn.models[modelName]) {
    return conn.models[modelName];
  }
  return conn.model(modelName, schema, collection);
}

/**
 * Resolve the tenant-scoped models for a given tenantId.
 * @param {string|ObjectId} tenantId
 * @returns {{ User, Installation, RepositoryData, Team, TeamMember,
 *            GitHubSecurityEvent, InstallationSummaryJob,
 *            TenantSettings, MemberInvite, connection }}
 */
function getTenantModels(tenantId) {
  const conn = getTenantDb(tenantId);
  const models = { connection: conn, tenantId: String(tenantId) };
  for (const def of TENANT_SCHEMAS) {
    models[def.modelName] = bindModel(conn, def);
  }
  return models;
}

module.exports = { getTenantModels, TENANT_SCHEMAS };
