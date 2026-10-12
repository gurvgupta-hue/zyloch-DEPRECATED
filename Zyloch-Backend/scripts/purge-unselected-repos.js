#!/usr/bin/env node
/**
 * Remove repository data nobody chose to monitor.
 *
 * Only the repositories a customer selects are to be stored. Before that rule,
 * the tenant databases collected more:
 *   1. `installation_repo_catalog` — every repository an installation could
 *      reach, with metadata, written to feed the repository chooser. The chooser
 *      now reads GitHub live and keeps the list in memory only.
 *   2. `installations.repoCatalog` — that catalog's sync status.
 *   3. `installations.repos` on an installation over its plan limit that has no
 *      selection yet — the first N names GitHub returned, chosen by nobody.
 *      (With a selection, `repos` must equal the selection.)
 *   4. `repositorydata` rows for repositories outside an installation's
 *      selection, e.g. from a sync that ran before the choice was made.
 *
 * Usage:  node scripts/purge-unselected-repos.js [--apply]
 *   Without --apply it only reports what it would change.
 */

const { connectCluster, getTenantDb, closeAll } = require('../db/connectionManager');
const { getControlModels } = require('../db/controlModels');

const CATALOG_COLLECTIONS = ['installation_repo_catalog', 'installationrepocatalogs'];

const fullNameOf = (row) => `${row.owner}/${row.repositoryName}`.toLowerCase();

async function purgeTenant(tenantId, apply) {
  const db = getTenantDb(tenantId);
  const report = { tenantId, catalogRowsDropped: 0, installations: [] };

  const existing = new Set((await db.db.listCollections({}, { nameOnly: true }).toArray()).map((c) => c.name));
  for (const name of CATALOG_COLLECTIONS) {
    if (!existing.has(name)) continue;
    report.catalogRowsDropped += await db.collection(name).countDocuments();
    if (apply) await db.collection(name).drop();
  }

  const installations = db.collection('installations');
  const repositoryData = db.collection('repositorydata');

  for (const inst of await installations.find({}).toArray()) {
    const selected = (inst.selectedRepos || []).map((name) => String(name).toLowerCase());
    const hasSelection = Boolean(inst.repoSelection?.completedAt) && selected.length > 0;
    const overLimit = Number.isFinite(inst.repoLimit) && Number(inst.repoCount) > inst.repoLimit;
    const entry = { installationId: inst.installationId, account: inst.account?.login };
    const set = {};
    const unset = {};

    if (inst.repoCatalog !== undefined) unset.repoCatalog = '';

    const repos = inst.repos || [];
    if (hasSelection) {
      const allowed = new Set(selected);
      const extra = repos.filter((name) => !allowed.has(String(name).toLowerCase()));
      if (extra.length) {
        entry.reposNotSelected = extra.length;
        set.repos = selected;
      }
    } else if (overLimit && repos.length) {
      entry.reposNotSelected = repos.length;
      set.repos = [];
    }

    if (hasSelection) {
      const allowed = new Set(selected);
      const stale = (
        await repositoryData
          .find({ installationId: inst.installationId })
          .project({ owner: 1, repositoryName: 1 })
          .toArray()
      ).filter((row) => !allowed.has(fullNameOf(row)));
      if (stale.length) {
        entry.repositoryDataNotSelected = stale.length;
        if (apply) await repositoryData.deleteMany({ _id: { $in: stale.map((row) => row._id) } });
      }
    }

    if (Object.keys(set).length || Object.keys(unset).length) {
      if (apply) {
        await installations.updateOne(
          { _id: inst._id },
          {
            ...(Object.keys(set).length ? { $set: set } : {}),
            ...(Object.keys(unset).length ? { $unset: unset } : {}),
          }
        );
      }
      entry.clearedCatalogStatus = 'repoCatalog' in unset;
    }

    if (Object.keys(entry).length > 2) report.installations.push(entry);
  }

  return report;
}

async function main() {
  const apply = process.argv.includes('--apply');
  await connectCluster();

  const tenantIds = (await getControlModels().InstallationIndex.distinct('tenantId')).map(String);
  console.log(`[purge] ${apply ? 'APPLYING' : 'Dry run'} across ${tenantIds.length} tenant(s) with installations`);

  for (const tenantId of tenantIds) {
    const report = await purgeTenant(tenantId, apply);
    if (report.catalogRowsDropped || report.installations.length) {
      console.log(JSON.stringify(report));
    }
  }

  if (!apply) console.log('[purge] Nothing was changed. Re-run with --apply to remove the data above.');
}

main()
  .catch((err) => {
    console.error('[purge] Failed:', err.message);
    process.exitCode = 1;
  })
  .finally(() => closeAll().catch(() => {}));
