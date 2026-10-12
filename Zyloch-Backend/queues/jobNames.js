/**
 * Job names carried on the installation-summary queue.
 *
 * Kept in their own module because `queues/summaryQueue.js` (through
 * `queues/connection.js`) exits the process when REDIS_URL is unset. Anything
 * that only needs the name — the worker's branch, the selection service, a test
 * — can import this without dragging a Redis connection along.
 */
module.exports = Object.freeze({
  SUMMARY_JOB: 'process-installation',
  // No longer queued: the chooser's repository list is read live and never
  // stored. Kept so the worker can recognise and drop jobs queued before that.
  RETIRED_REPO_CATALOG_JOB: 'sync-repo-catalog',
});
