const { Worker } = require('bullmq');
const connection = require('../queues/connection');
const { getTenantModels } = require('../db/tenantModels');
const { processInstallationSummary, processIncrementalInstallationSummary } = require('../jobs/fetchInstallationSummary');
const { RETIRED_REPO_CATALOG_JOB } = require('../queues/jobNames');


let summaryWorker = null;

/**
 * Move a job's Mongo document to `failed` once BullMQ has given up on it.
 *
 * This is the single authority on recording failure, and it lives here rather
 * than in the job function because it is the only place that sees *every* way a
 * job can die: a throw before the function's own try block, a stall after the
 * worker was killed, or an ordinary error. A job document left on `pending` is
 * not a cosmetic problem — the overview page reads `pending` as "still working"
 * and polls it every two seconds for ten minutes before showing anything at all.
 *
 * Only the final attempt writes. Marking `failed` after attempt 1 of 3 would
 * show the user a failure for a job that is about to run again.
 */
async function recordTerminalFailure(job, error) {
  if (!job) return;

  // Jobs without a `mongoJobId` (e.g. a retired catalog-sync job) have no
  // summary document to mark, so this returns early for them.
  const { tenantId, mongoJobId } = job.data || {};
  const exhausted = job.attemptsMade >= (job.opts?.attempts || 1);
  if (!exhausted || !tenantId || !mongoJobId) return;

  try {
    const { InstallationSummaryJob } = getTenantModels(tenantId);
    await InstallationSummaryJob.findByIdAndUpdate(mongoJobId, {
      status: 'failed',
      error: error.message,
      progress: 100,
    });
  } catch (writeErr) {
    console.error(
      `Could not mark job document ${mongoJobId} failed (it will keep polling):`,
      writeErr.message
    );
  }
}

function startSummaryWorker() {
  if (summaryWorker) return summaryWorker;
  console.log('Starting installation summary worker...');

  summaryWorker = new Worker('installation-summary', async (job) => {
    console.log(` Processing job ${job.id} for installation ${job.data.installationId}`);
    
    try {
      const { installationId, isIncremental } = job.data;

      // The repository catalog is no longer stored (the chooser reads GitHub
      // live, services/repoCatalog.js). A catalog job still queued from before
      // must be dropped here: falling through would run a full summary sync.
      if (job.name === RETIRED_REPO_CATALOG_JOB) {
        console.log(` Dropping retired repository-catalog job for installation ${installationId}`);
        return { skipped: true, reason: 'repo_catalog_retired' };
      }

      // Check if this should be an incremental fetch
      if (isIncremental) {
        console.log(` Using incremental fetch for installation ${installationId}`);
        const result = await processIncrementalInstallationSummary(job);
        return result;
      }
      
      // Use full fetch
      console.log(` Using full fetch for installation ${installationId}`);
      const result = await processInstallationSummary(job);
      return result;
    } catch (error) {
      throw error;
    }
  }, {
    connection,
    concurrency: 5,
    limiter: {
      max: 50,
      duration: 60000,
    },
    settings: {
      stalledInterval: 300000,
      maxStalledCount: 2,
    },
  });

  summaryWorker.on('completed', (job, result) => {
    console.log(` Job ${job.id} completed successfully`);
  });

  summaryWorker.on('failed', async (job, error) => {
    console.error(`? Job ${job?.id} failed:`, error.message);
    console.error(`   Attempt ${job?.attemptsMade} of ${job?.opts?.attempts}`);
    await recordTerminalFailure(job, error);
  });

  summaryWorker.on('stalled', (jobId) => {
    console.warn(`?? Job ${jobId} has stalled`);
  });

  summaryWorker.on('error', (error) => {
    console.error('?? Worker error:', error);
  });

  console.log('Summary worker started successfully');
  return summaryWorker;
}

async function stopSummaryWorker() {
  if (summaryWorker) {
    await summaryWorker.close();
    summaryWorker = null;
    console.log('Summary worker stopped');
  }
}

module.exports = {
  startSummaryWorker,
  stopSummaryWorker,
};
