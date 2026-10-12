/**
 * Tenant lifecycle service: provision and offboard tenants on the shared cluster.
 *
 * Provisioning steps for a brand new tenant:
 *   1. Create the slim control-plane `organizations` document (its _id is the tenantId
 *      and determines the tenant DB name).
 *   2. Ensure indexes exist on the tenant DB collections.
 *   3. Seed the singleton `tenant_settings` document.
 *   4. Seed the control-plane `tenant_licenses` and `tenant_metrics` documents.
 */

const mongoose = require('mongoose');
const { getControlModels } = require('../db/controlModels');
const { getTenantModels } = require('../db/tenantModels');
const { tenantDbName } = require('../db/connectionManager');

const DEFAULT_PLAN_ID = process.env.DEFAULT_LICENSE_PLAN_ID || 'basic';
const TENANT_INDEXES_VERSION = 1;

/** Compile every tenant model index. Safe to call repeatedly (idempotent). */
async function ensureTenantIndexes(tenantId) {
  const models = getTenantModels(tenantId);
  const builders = Object.values(models).filter(
    (m) => m && typeof m.createIndexes === 'function'
  );
  await Promise.all(builders.map((model) => model.createIndexes()));
  return models;
}

/** Seed the singleton tenant_settings doc if missing. */
async function seedTenantSettings(tenantId) {
  const { TenantSettings } = getTenantModels(tenantId);
  await TenantSettings.updateOne(
    { tenantId },
    { $setOnInsert: { tenantId } },
    { upsert: true }
  );
}

/** Seed control-plane license + metrics docs for the tenant. */
async function seedControlRecords(tenantId, { planId = DEFAULT_PLAN_ID } = {}) {
  const { TenantLicense, TenantMetrics } = getControlModels();
  await Promise.all([
    TenantLicense.updateOne(
      { tenantId },
      { $setOnInsert: { tenantId, planId, status: 'active', startsAt: new Date() } },
      { upsert: true }
    ),
    TenantMetrics.updateOne({ tenantId }, { $setOnInsert: { tenantId } }, { upsert: true }),
  ]);
}

/**
 * Undo a half-finished provision.
 *
 * Without this, a failure partway through leaves an `organizations` row stranded
 * in `provisioning` state. If that row carried a domain it also keeps the domain
 * claim forever, so the user's own retry can no longer claim its own domain and
 * silently lands in a second, domainless tenant — and every further retry
 * strands another tenant database. Deleting the row is what makes a retry a
 * retry rather than an accumulation.
 *
 * Best-effort by design: a rollback failure must never mask the original error,
 * which is the one that explains what actually went wrong.
 */
async function rollbackFailedProvision(tenantId, cause) {
  const { Organization, TenantLicense, TenantMetrics } = getControlModels();
  console.warn(`[provision] Rolling back tenant ${tenantId} after failure: ${cause.message}`);

  try {
    await getTenantModels(tenantId).connection.dropDatabase();
    await Promise.all([
      // Scoped to `provisioning` so a tenant that somehow reached active is never
      // removed by a late-arriving rollback.
      Organization.deleteOne({ _id: tenantId, provisionStatus: 'provisioning' }),
      TenantLicense.deleteOne({ tenantId }),
      TenantMetrics.deleteOne({ tenantId }),
    ]);
  } catch (err) {
    console.error(
      `[provision] Rollback for tenant ${tenantId} failed, manual cleanup may be needed: ${err.message}`
    );
  }
}

/**
 * Provision a fresh tenant.
 *
 * The generated organization `_id` is the tenant's only identity — it names the
 * database and is what `?org_id=` carries on an invite link. `domain` is a label
 * recorded alongside it; several organizations may share one, so provisioning
 * never consults or competes for it.
 *
 * @param {object} args
 * @param {string} args.name             Organization display name
 * @param {string} [args.domain]         Informational email domain, or null
 * @param {ObjectId} [args.adminUserId]  Admin user _id (created by caller in tenant DB)
 * @param {ObjectId} [args.tenantId]     Pre-generated tenant/org _id
 * @returns {Promise<{ organization, tenantId, databaseName, models }>}
 */
async function provisionTenant({ name, domain = null, adminUserId = null, tenantId }) {
  const { Organization } = getControlModels();

  const orgId = tenantId || new mongoose.Types.ObjectId();
  const databaseName = tenantDbName(orgId);

  const baseDoc = {
    _id: orgId,
    name,
    adminUserId: adminUserId || null,
    databaseName,
    provisionStatus: 'provisioning',
    indexesVersion: 0,
  };

  // No duplicate-domain fallback: `domain` carries no uniqueness, so this write
  // cannot collide on it. A colleague signing up from the same company simply
  // gets their own organization.
  const organization = await Organization.create({ ...baseDoc, domain: domain || null });

  try {
    await ensureTenantIndexes(orgId);
    await seedTenantSettings(orgId);
    await seedControlRecords(orgId);

    organization.provisionStatus = 'active';
    organization.indexesVersion = TENANT_INDEXES_VERSION;
    organization.provisionedAt = new Date();
    await organization.save();
  } catch (err) {
    await rollbackFailedProvision(orgId, err);
    throw err;
  }

  return {
    organization,
    tenantId: orgId,
    databaseName,
    models: getTenantModels(orgId),
  };
}

/**
 * Offboard a tenant by dropping its database and removing control-plane routing.
 * Records a platform_event with a final snapshot reference.
 * NOTE: drop strategy (full dropDatabase) is the agreed default; revisit before MT-C-04.
 */
async function offboardTenant(tenantId, { actorUserId = null } = {}) {
  const { Organization, AuthIdentity, InstallationIndex, TenantLicense, TenantMetrics, PlatformEvent } =
    getControlModels();

  const organization = await Organization.findById(tenantId);
  if (!organization) {
    throw new Error('Organization not found for offboarding');
  }

  organization.provisionStatus = 'offboarding';
  await organization.save();

  // Drop the entire tenant database (shared cluster, isolated DB).
  const tenantConn = getTenantModels(tenantId).connection;
  await tenantConn.dropDatabase();

  await Promise.all([
    AuthIdentity.deleteMany({ tenantId }),
    InstallationIndex.deleteMany({ tenantId }),
    TenantLicense.deleteOne({ tenantId }),
    TenantMetrics.deleteOne({ tenantId }),
  ]);

  organization.isActive = false;
  organization.provisionStatus = 'offboarded';
  await organization.save();

  await PlatformEvent.create({
    tenantId,
    eventType: 'tenant.offboarded',
    actorUserId,
    payload: { databaseName: organization.databaseName },
    occurredAt: new Date(),
  });

  return { tenantId: String(tenantId), offboarded: true };
}

module.exports = {
  provisionTenant,
  offboardTenant,
  ensureTenantIndexes,
  seedTenantSettings,
  seedControlRecords,
  rollbackFailedProvision,
  TENANT_INDEXES_VERSION,
};
