const createError = require('../utils/createError');
const { getTenantByInstallationId } = require('../services/authRouting');
const { getControlModels } = require('../db/controlModels');
const { getTenantModels } = require('../db/tenantModels');

/**
 * Verify a GitHub installation belongs to `tenantId` and return the tenant DB document.
 *
 * Strategy C: ownership is resolved via control-plane `installation_index.tenantId`.
 * The legacy `Installation.zylochOrganizationId` field was removed — the tenant DB
 * boundary is the scope; this helper closes IDOR on raw `installationId` params.
 *
 * @param {number|string} installationId GitHub App installation id
 * @param {string} tenantId Organization / tenant ObjectId string
 * @param {{ getTenantByInstallationId?: Function, getTenantModels?: Function }} [deps] Test doubles
 * @returns {Promise<object>} Installation document (lean)
 */
async function assertInstallationBelongsToTenant(installationId, tenantId, deps = {}) {
  const resolveOwnerTenant = deps.getTenantByInstallationId || getTenantByInstallationId;
  const resolveTenantModels = deps.getTenantModels || getTenantModels;

  const ghId = Number(installationId);
  if (!Number.isFinite(ghId) || ghId <= 0) {
    throw createError(404, 'Installation not found');
  }

  const ownerTenantId = await resolveOwnerTenant(ghId);
  if (!ownerTenantId) {
    throw createError(404, 'Installation not found');
  }

  if (String(ownerTenantId) !== String(tenantId)) {
    throw createError(403, 'Installation does not belong to your organization');
  }

  const { Installation } = resolveTenantModels(tenantId);
  const installation = await Installation.findOne({ installationId: ghId }).lean();
  if (!installation) {
    throw createError(404, 'Installation not found');
  }

  return installation;
}

/**
 * List installations explicitly scoped to a tenant via installation_index.
 * Avoids unfiltered Installation.find({}) — Strategy C equivalent of
 * zylochOrganizationId === tenantId.
 *
 * @param {string} tenantId
 * @param {{ getControlModels?: Function, getTenantModels?: Function }} [deps]
 * @returns {Promise<object[]>}
 */
async function listInstallationsForTenant(tenantId, deps = {}) {
  const getControl = deps.getControlModels || getControlModels;
  const resolveTenantModels = deps.getTenantModels || getTenantModels;

  if (!tenantId) {
    return [];
  }

  const { InstallationIndex } = getControl();
  const indexed = await InstallationIndex.find({ tenantId })
    .select('githubInstallationId')
    .lean();

  if (indexed.length === 0) {
    return [];
  }

  const installationIds = indexed.map((row) => row.githubInstallationId);
  const { Installation } = resolveTenantModels(tenantId);
  return Installation.find({ installationId: { $in: installationIds } }).lean();
}

module.exports = { assertInstallationBelongsToTenant, listInstallationsForTenant };
