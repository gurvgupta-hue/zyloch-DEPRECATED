/**
 * Control-plane bootstrap: ensure indexes and seed the default license plan
 * catalog. Invoked once at server startup after the control DB connects.
 */

const { getControlModels } = require('../db/controlModels');
const { buildCatalog, mergeCatalog } = require('./capabilityCatalog');

/**
 * The plans a brand-new control plane starts with.
 *
 * Data, not code, and seeded with `$setOnInsert` — so this file only ever
 * describes a *fresh* cluster. Once a plan exists, the platform console is the
 * only thing that edits it, and nothing here can overwrite an admin's decision.
 * Editing this file therefore changes what new environments get, never what a
 * running one already has.
 */
const DEFAULT_PLANS = require('../config/licensePlans.seed.json');

/**
 * List a collection's indexes, treating a missing collection as "no indexes".
 * A fresh cluster has nothing to reconcile.
 */
async function listIndexes(model) {
  try {
    return await model.collection.indexes();
  } catch (err) {
    if (err.codeName === 'NamespaceNotFound' || err.code === 26) return [];
    throw err;
  }
}

/** True when `idx` is keyed on exactly `keys`, each ascending. */
function isKeyedOn(idx, keys) {
  if (!idx.key) return false;
  const actual = Object.keys(idx.key);
  return actual.length === keys.length && keys.every((k) => idx.key[k] === 1);
}

/**
 * Drop the pre-MT-07 `organizations.domain` index so the partial one can replace it.
 *
 * The old index was a plain `{ domain: 1 }, { unique: true }`. MongoDB rejects
 * `createIndexes()` for the same key with different options
 * (`IndexOptionsConflict`, code 85), so an existing deployment would fail to boot
 * without this. Dropping is safe: it is immediately recreated below, and the
 * partial version enforces strictly less than the old one.
 */
async function reconcileOrganizationDomainIndex() {
  const { Organization } = getControlModels();

  const domainIndex = (await listIndexes(Organization)).find((idx) => isKeyedOn(idx, ['domain']));

  if (domainIndex && !domainIndex.partialFilterExpression) {
    console.log(
      `[control] Dropping legacy index "${domainIndex.name}" on organizations.domain ` +
        '(replaced by a partial unique index so unclaimed tenants can share a null domain)'
    );
    await Organization.collection.dropIndex(domainIndex.name);
  }
}

/**
 * Drop the pre-KAN-49 unique `auth_identities.{provider, providerId}` index.
 *
 * One OAuth identity used to map to exactly one tenant, so that pair was unique.
 * KAN-49 made an identity joinable to many tenants (one row per tenant): the
 * uniqueness moved to `{provider, providerId, tenantId}` and the two-key index
 * stayed on only as a non-unique lookup index. Same `IndexOptionsConflict` as
 * above — the name and key match but `unique` differs — so an existing
 * deployment cannot boot until the unique version is dropped. It is recreated
 * non-unique immediately below.
 */
async function reconcileAuthIdentityProviderIndex() {
  const { AuthIdentity } = getControlModels();

  const providerIndex = (await listIndexes(AuthIdentity)).find((idx) =>
    isKeyedOn(idx, ['provider', 'providerId'])
  );

  if (providerIndex && providerIndex.unique) {
    console.log(
      `[control] Dropping legacy unique index "${providerIndex.name}" on auth_identities ` +
        '(an identity may now belong to multiple tenants; uniqueness moved to ' +
        '{provider, providerId, tenantId})'
    );
    await AuthIdentity.collection.dropIndex(providerIndex.name);
  }
}

async function ensureControlIndexes() {
  await reconcileOrganizationDomainIndex();
  await reconcileAuthIdentityProviderIndex();

  const models = getControlModels();
  const builders = Object.entries(models)
    .filter(([key]) => key !== 'connection')
    .map(([, model]) => model)
    .filter((m) => m && typeof m.createIndexes === 'function');
  await Promise.all(builders.map((model) => model.createIndexes()));
}

async function seedLicensePlans() {
  const { LicensePlan } = getControlModels();
  await Promise.all(
    DEFAULT_PLANS.map((plan) =>
      LicensePlan.updateOne({ planId: plan.planId }, { $setOnInsert: plan }, { upsert: true })
    )
  );
}

/**
 * Publish the capability catalog to the control DB (MT pricing model).
 *
 * This build knows which scanners exist, so it reconciles keys on every boot and
 * a newly shipped scanner shows up in plan authoring without a console deploy.
 * It deliberately does not republish wholesale: the platform console can edit
 * labels, grouping, ordering and limits, and this runs on every process start —
 * an overwrite here would erase those edits on the next restart, not merely the
 * next deploy. `mergeCatalog` decides what may be overwritten; see its comment.
 */
async function publishCapabilityCatalog() {
  const { getControlDb } = require('../db/connectionManager');
  const collection = getControlDb().collection('capability_catalog');

  const stored = await collection.findOne({ _id: 'current' });
  const fresh = buildCatalog();
  const catalog = mergeCatalog(stored, fresh);

  await collection.updateOne(
    { _id: 'current' },
    { $set: { ...catalog, _id: 'current' } },
    { upsert: true }
  );

  const scannerCount = catalog.scannerGroups.reduce((n, g) => n + g.scanners.length, 0);
  const mode = !stored
    ? 'seeded'
    : Number(fresh.version) > (Number(stored.version) || 0)
      ? `reshaped to v${fresh.version} (console presentation edits superseded)`
      : 'reconciled (console edits preserved)';
  console.log(
    `[control] Capability catalog v${catalog.version} ${mode} ` +
      `(${scannerCount} scanners in ${catalog.scannerGroups.length} groups, ${catalog.features.length} features)`
  );
}

async function bootstrapControlPlane() {
  await ensureControlIndexes();
  await seedLicensePlans();
  await publishCapabilityCatalog();
  console.log('[control] Indexes ensured, license plans seeded, catalog published');
}

module.exports = {
  bootstrapControlPlane,
  publishCapabilityCatalog,
  ensureControlIndexes,
  reconcileOrganizationDomainIndex,
  reconcileAuthIdentityProviderIndex,
  seedLicensePlans,
  DEFAULT_PLANS,
};
