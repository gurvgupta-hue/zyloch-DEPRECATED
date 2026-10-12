/**
 * Standalone cron: periodically enqueue incremental refreshes for every tenant's
 * installations. Tenant-aware for Strategy C — iterates active organizations in
 * the control plane and enqueues per-tenant jobs (each carrying its tenantId).
 *
 * Run as its own process (requires `node-cron`): `node corn/refreshSummaries.js`.
 */

const cron = require('node-cron');
const connectDB = require('../config/db');
const { closeAll } = require('../db/connectionManager');
const { getControlModels } = require('../db/controlModels');
const { getTenantModels } = require('../db/tenantModels');
const summaryQueue = require('../queues/summaryQueue');

async function enqueueTenantRefreshes() {
  const { Organization } = getControlModels();
  const orgs = await Organization.find({ isActive: true, provisionStatus: 'active' })
    .select('_id')
    .lean();

  for (const org of orgs) {
    const tenantId = String(org._id);
    const { Installation, InstallationSummaryJob } = getTenantModels(tenantId);
    const installations = await Installation.find({}).lean();

    for (const installation of installations) {
      try {
        const installationId = installation.installationId;
        const accountId = installation.account?.id;
        const login = installation.account?.login;
        const accountType = installation.account?.type || 'User';

        const job = await InstallationSummaryJob.findOneAndUpdate(
          { tenantId, installationId, accountId },
          {
            // `tenantId` must not repeat in `$set` — MongoDB rejects a path
            // written by two operators ("would create a conflict at 'tenantId'").
            $setOnInsert: { tenantId, installationId, login, accountId, accountType, createdAt: new Date() },
            $set: { status: 'pending', progress: 0, error: null, updatedAt: new Date() },
          },
          { upsert: true, new: true }
        );

        await summaryQueue.add(
          'process-installation',
          {
            tenantId,
            installationId,
            login,
            accountId,
            accountType,
            mongoJobId: job._id,
            isIncremental: !!installation.lastFetchedAt,
          },
          { jobId: `cron-refresh-${tenantId}-${installationId}-${Date.now()}`, priority: 5 }
        );

        await new Promise((r) => setTimeout(r, 250));
      } catch (err) {
        console.error(`[Cron] Failed for tenant ${tenantId} installation:`, err.message);
      }
    }
  }
}

async function main() {
  await connectDB();
  // Runs every 12 hours
  cron.schedule('0 */12 * * *', async () => {
    console.log('[Cron] Auto-refresh installation summaries started');
    try {
      await enqueueTenantRefreshes();
    } catch (err) {
      console.error('[Cron] Auto-refresh failed:', err.message);
    }
  });
}

if (require.main === module) {
  main().catch((err) => {
    console.error('[Cron] Fatal:', err.message);
    process.exit(1);
  });

  ['SIGINT', 'SIGTERM'].forEach((signal) =>
    process.on(signal, async () => {
      await closeAll();
      process.exit(0);
    })
  );
}

module.exports = { enqueueTenantRefreshes };
