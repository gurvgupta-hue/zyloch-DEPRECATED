/**
 * One summary run per installation at a time, and a progress value that only
 * moves forward.
 *
 * Every entry point that starts a sync (dashboard load, manual refresh, push
 * webhook, retry) used to queue a fresh BullMQ job unconditionally, and the
 * worker runs several jobs concurrently. Two runs on one installation then
 * wrote to the same `progress` field — one at 60%, a newer one restarting from
 * 0 — which is what made the dashboard bar jump back to the left and stall.
 *
 * This module takes the queue and models as arguments rather than requiring
 * them, so it carries no Redis connection and stays unit-testable.
 */

// BullMQ 5 states for a job that has not finished. A waiting job that was added
// with a priority reports `prioritized`, not `waiting`.
const LIVE_STATES = new Set(['waiting', 'prioritized', 'delayed', 'active', 'waiting-children']);

/**
 * The BullMQ job currently working on this summary document, if it is still
 * queued or running. A lookup failure is treated as "none" — the caller then
 * starts a run, which is the safe side of the choice.
 *
 * @returns {Promise<{ bullJob: object, state: string } | null>}
 */
async function findLiveRun(queue, summaryJob) {
  const bullmqJobId = summaryJob?.bullmqJobId;
  if (!bullmqJobId || typeof queue?.getJob !== 'function') return null;

  try {
    const bullJob = await queue.getJob(bullmqJobId);
    if (!bullJob) return null;
    const state = await bullJob.getState();
    return LIVE_STATES.has(state) ? { bullJob, state } : null;
  } catch (err) {
    console.warn(`[SummaryRuns] Could not read BullMQ job ${bullmqJobId}: ${err.message}`);
    return null;
  }
}

/**
 * Record a run's progress without ever moving it backwards.
 *
 * The concurrent per-repository workers finish their writes out of order, and a
 * BullMQ retry restarts from 0; both used to drag the stored value back. The
 * write is also ignored when another run owns the document, so an orphaned run
 * cannot overwrite the current one.
 */
async function reportProgress(job, SummaryJobModel, mongoJobId, progress) {
  const value = Math.max(0, Math.min(100, Math.floor(Number(progress) || 0)));

  try {
    await job.updateProgress(value);
  } catch (_) {
    // BullMQ's own copy is diagnostic only; the document is what the UI reads.
  }

  await SummaryJobModel.updateOne(
    {
      _id: mongoJobId,
      progress: { $lt: value },
      $or: [{ bullmqJobId: String(job.id) }, { bullmqJobId: null }],
    },
    { $set: { progress: value } }
  );
}

module.exports = { LIVE_STATES, findLiveRun, reportProgress };
