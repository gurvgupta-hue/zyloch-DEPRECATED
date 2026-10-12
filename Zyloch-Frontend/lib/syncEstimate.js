/**
 * How long a first population of the dashboard takes, and how to say it.
 *
 * The first sync walks every selected repository for branches, commits and
 * languages, rate-limited by GitHub. For a handful of repos that is minutes; for
 * an org with thousands it genuinely runs for hours. Showing a bare spinner for
 * that long reads as "broken", so the sync screen states the window up front and
 * narrows it to a live estimate once the job reports real progress.
 */

/** Ordered bands: the first whose `upTo` covers the repo count wins. */
const BANDS = [
  { upTo: 100, minMinutes: 2, maxMinutes: 10, label: "a few minutes" },
  { upTo: 500, minMinutes: 10, maxMinutes: 30, label: "about 10–30 minutes" },
  { upTo: 2000, minMinutes: 30, maxMinutes: 120, label: "about 30 minutes to 2 hours" },
  { upTo: 5000, minMinutes: 120, maxMinutes: 360, label: "about 2 to 6 hours" },
  { upTo: 10000, minMinutes: 360, maxMinutes: 720, label: "about 6 to 12 hours" },
  { upTo: Infinity, minMinutes: 720, maxMinutes: 1440, label: "up to 24 hours" },
];

export function estimateSyncWindow(repoCount) {
  const count = Number(repoCount) || 0;
  const band = BANDS.find((b) => count <= b.upTo) || BANDS[BANDS.length - 1];
  return { ...band, repoCount: count };
}

/** "2h 14m", "45m", "30s" — compact, no library. */
export function formatDuration(ms) {
  const total = Math.max(Math.round(Number(ms) || 0), 0);
  const seconds = Math.floor(total / 1000);
  if (seconds < 60) return `${seconds}s`;

  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m`;

  const hours = Math.floor(minutes / 60);
  const restMinutes = minutes % 60;
  if (hours < 24) return restMinutes ? `${hours}h ${restMinutes}m` : `${hours}h`;

  const days = Math.floor(hours / 24);
  const restHours = hours % 24;
  return restHours ? `${days}d ${restHours}h` : `${days}d`;
}

/**
 * Remaining time from observed progress, or null when there is not enough of it
 * to say anything honest.
 *
 * Below 5% the extrapolation swings wildly (a 3-second head start would promise
 * "4 minutes" for a 12-hour job), so the caller falls back to the volume band.
 */
export function estimateRemaining({ progress, startedAt, now = Date.now() }) {
  const pct = Number(progress) || 0;
  if (!startedAt || pct < 5 || pct >= 100) return null;

  const elapsed = now - new Date(startedAt).getTime();
  if (!Number.isFinite(elapsed) || elapsed <= 0) return null;

  const remaining = elapsed * ((100 - pct) / pct);
  if (!Number.isFinite(remaining) || remaining <= 0) return null;
  return remaining;
}

/** The sentence under the progress bar. */
export function syncEtaLabel({ repoCount, progress, startedAt, now = Date.now() }) {
  const remaining = estimateRemaining({ progress, startedAt, now });
  if (remaining) return `about ${formatDuration(remaining)} left`;
  return `This usually takes ${estimateSyncWindow(repoCount).label}`;
}

export default { estimateSyncWindow, estimateRemaining, syncEtaLabel, formatDuration };
