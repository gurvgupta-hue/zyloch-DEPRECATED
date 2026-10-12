#!/usr/bin/env node
/**
 * Export the live capability catalog back into the committed seed file.
 *
 * The console can edit the catalog, and those edits live only in the control DB.
 * A brand-new environment (staging, a fresh cluster, an on-prem install) seeds
 * from `config/capabilityCatalog.seed.json` and would otherwise come up with a
 * shape no admin has seen since day one. Running this after a console change and
 * committing the diff is what keeps new environments current.
 *
 * Usage:  node scripts/export-capability-catalog.js [--check]
 *   --check  exit non-zero if the seed file is behind the live catalog, and
 *            write nothing. Intended for CI, to catch an unexported edit.
 */

const fs = require('fs');
const path = require('path');

const { connectCluster, getControlDb, closeAll } = require('../db/connectionManager');

const SEED_PATH = path.join(__dirname, '..', 'config', 'capabilityCatalog.seed.json');

/**
 * Reduce a stored catalog document to the fields the seed file owns.
 *
 * `unlimitedValue`, `featureLevels` and `updatedAt` are derived at build time
 * rather than authored, and `_id`/`revision` are storage concerns — round-tripping
 * any of them would produce a diff on every export.
 */
function toSeed(catalog) {
  return {
    version: catalog.version,
    limits: catalog.limits,
    scannerGroups: catalog.scannerGroups.map((g) => ({
      id: g.id,
      label: g.label,
      ...(g.help ? { help: g.help } : {}),
      scanners: g.scanners,
    })),
    features: catalog.features.map((f) => ({
      key: f.key,
      label: f.label,
      group: f.group,
      ...(f.help ? { help: f.help } : {}),
      levels: f.levels || null,
    })),
  };
}

async function main() {
  const checkOnly = process.argv.includes('--check');

  await connectCluster();
  const stored = await getControlDb().collection('capability_catalog').findOne({ _id: 'current' });

  if (!stored) {
    console.error('[catalog] No catalog in the control DB — start the server once to seed it.');
    process.exitCode = 1;
    return;
  }

  const next = `${JSON.stringify(toSeed(stored), null, 2)}\n`;
  const current = fs.existsSync(SEED_PATH) ? fs.readFileSync(SEED_PATH, 'utf8') : '';

  if (next === current) {
    console.log('[catalog] Seed file already matches the live catalog.');
    return;
  }

  if (checkOnly) {
    console.error(
      '[catalog] Seed file is behind the live catalog. ' +
        'Run "node scripts/export-capability-catalog.js" and commit the result.'
    );
    process.exitCode = 1;
    return;
  }

  fs.writeFileSync(SEED_PATH, next);
  console.log(`[catalog] Wrote ${path.relative(process.cwd(), SEED_PATH)} at v${stored.version}.`);
}

if (require.main === module) {
  main()
    .catch((err) => {
      console.error('[catalog] Export failed:', err.message);
      process.exitCode = 1;
    })
    .finally(closeAll);
}

module.exports = { toSeed, SEED_PATH };
