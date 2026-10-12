/**
 * Dynamic license-limit enforcement.
 *
 * Limits (maxRepos, maxUsers, maxScansPerMonth, maxScansPerDay) come from the
 * tenant's effective plan entitlements in the control DB — never from hardcoded
 * env flags.
 *
 * Two behaviours the pricing model depends on:
 *   - A negative limit means UNLIMITED, so per-seat and Enterprise plans are
 *     uncapped without reading as "zero allowed".
 *   - A limit in 'soft' mode lets the request through and records an overage,
 *     which is how a "soft limit with overages" tier is sold.
 */

const createError = require('../utils/createError');
const { getControlModels } = require('../db/controlModels');
const { getTenantModels } = require('../db/tenantModels');
const { resolveTenantEntitlements, limitMode } = require('./licenseEntitlements');

const LIMIT_KEYS = Object.freeze({
  MAX_REPOS: 'maxRepos',
  MAX_USERS: 'maxUsers',
  MAX_SCANS_PER_MONTH: 'maxScansPerMonth',
  MAX_SCANS_PER_DAY: 'maxScansPerDay',
});

function currentMonthKey(date = new Date()) {
  return date.toISOString().slice(0, 7); // YYYY-MM
}

/**
 * Resolve a numeric limit.
 *
 * A negative value is the UNLIMITED sentinel and resolves to Infinity, so every
 * `current >= limit` comparison below is naturally false for uncapped plans.
 * Absent or malformed values resolve to 0 ("none allowed"), which is a real and
 * different thing from uncapped.
 */
function readLimit(entitlements, key, absentDefault = 0) {
  const resolve = (raw) => {
    const value = Number(raw);
    if (!Number.isFinite(value)) return 0;
    if (value < 0) return Number.POSITIVE_INFINITY;
    return Math.floor(value);
  };

  if (!entitlements) return resolve(absentDefault);
  const raw = entitlements[key];
  // An absent limit is not the same as a zero limit. Callers pass
  // `absentDefault` to say which way an omission should fall — the daily scan
  // ceiling defaults to UNLIMITED, because a plan that only states a monthly
  // figure must not be read as "zero scans per day".
  if (raw == null || raw === '') return resolve(absentDefault);
  return resolve(raw);
}

/** Absent-value default per limit key. */
const LIMIT_ABSENT_DEFAULTS = Object.freeze({
  maxScansPerDay: -1, // UNLIMITED — plans may specify only a monthly ceiling
});

function readPlanLimit(entitlements, key) {
  return readLimit(entitlements, key, LIMIT_ABSENT_DEFAULTS[key] ?? 0);
}

function limitExceededError(key, limit, current) {
  const err = createError(
    403,
    `License limit exceeded for ${key}: ${current}/${limit}. Upgrade your plan or remove unused resources.`
  );
  err.code = 'LICENSE_LIMIT_EXCEEDED';
  err.limitKey = key;
  err.limit = limit;
  err.current = current;
  return err;
}

/**
 * Resolve effective limits for a tenant from license_plans + overrides.
 * @returns {Promise<{
 *   tenantId: string,
 *   active: boolean,
 *   planId: string|null,
 *   maxRepos: number,
 *   maxUsers: number,
 *   maxScansPerMonth: number,
 *   entitlements: object,
 * }>}
 */
async function resolveTenantLimits(tenantId) {
  const resolved = await resolveTenantEntitlements(tenantId);
  const entitlements = resolved.entitlements || {};
  return {
    tenantId: String(tenantId),
    active: !!resolved.active,
    planId: resolved.planId,
    maxRepos: readPlanLimit(entitlements, LIMIT_KEYS.MAX_REPOS),
    maxUsers: readPlanLimit(entitlements, LIMIT_KEYS.MAX_USERS),
    maxScansPerMonth: readPlanLimit(entitlements, LIMIT_KEYS.MAX_SCANS_PER_MONTH),
    maxScansPerDay: readPlanLimit(entitlements, LIMIT_KEYS.MAX_SCANS_PER_DAY),
    entitlements,
  };
}

async function countTenantUsers(tenantId, { activeOnly = true } = {}) {
  const { User } = getTenantModels(tenantId);
  const filter = activeOnly ? { isActive: { $ne: false } } : {};
  return User.countDocuments(filter);
}

async function countTenantRepos(tenantId) {
  const { RepositoryData } = getTenantModels(tenantId);
  return RepositoryData.countDocuments({});
}

async function getMonthlyScanUsage(tenantId) {
  const { TenantMetrics } = getControlModels();
  const metrics = await TenantMetrics.findOne({ tenantId }).lean();
  const monthKey = currentMonthKey();
  if (!metrics || metrics.scanMonthKey !== monthKey) {
    return { count: 0, monthKey };
  }
  return { count: Number(metrics.scanCountThisMonth) || 0, monthKey };
}

/** Scans recorded for the current UTC day, from the rolling window buckets. */
async function getDailyScanUsage(tenantId, { at = new Date() } = {}) {
  const { TenantMetrics } = getControlModels();
  const metrics = await TenantMetrics.findOne({ tenantId }).lean();
  const dayKey = currentDayKey(at);
  const bucket = (metrics?.scanDaily || []).find((b) => b?.date === dayKey);
  return { count: Number(bucket?.count) || 0, dayKey };
}

/**
 * Cap a repo list to the tenant's maxRepos (stable order preserved).
 * An unlimited plan resolves maxRepos to Infinity and keeps everything.
 */
function capReposToLimit(repos, maxRepos) {
  if (!Array.isArray(repos)) return [];
  if (maxRepos === Number.POSITIVE_INFINITY) return repos;
  if (!Number.isFinite(maxRepos) || maxRepos <= 0) return [];
  if (repos.length <= maxRepos) return repos;
  return repos.slice(0, maxRepos);
}

async function resolveLimitContext(tenantId, { entitlements, active } = {}) {
  if (entitlements) {
    return {
      active: active !== false,
      maxRepos: readPlanLimit(entitlements, LIMIT_KEYS.MAX_REPOS),
      maxUsers: readPlanLimit(entitlements, LIMIT_KEYS.MAX_USERS),
      maxScansPerMonth: readPlanLimit(entitlements, LIMIT_KEYS.MAX_SCANS_PER_MONTH),
      maxScansPerDay: readPlanLimit(entitlements, LIMIT_KEYS.MAX_SCANS_PER_DAY),
      entitlements,
    };
  }
  return resolveTenantLimits(tenantId);
}

/**
 * Decide what to do about one limit.
 *
 * @returns {{ exceeded: boolean, mode: 'hard'|'soft', limit: number, current: number }}
 */
function evaluateLimit(limitKey, { current, limit, entitlements }) {
  const exceeded = Number.isFinite(limit) && current >= limit;
  return {
    exceeded,
    mode: limitMode(entitlements, limitKey),
    limit,
    current,
  };
}

/**
 * Record that a tenant went past a soft limit, for billing to pick up.
 *
 * Overages are counted per calendar month per limit, and a `usage.overage`
 * platform event is written the first time each month so support/billing has a
 * timeline rather than only a running total.
 */
async function recordOverage(tenantId, limitKey, { limit, current, at = new Date() } = {}) {
  const { TenantMetrics, PlatformEvent } = getControlModels();
  const monthKey = currentMonthKey(at);
  const field = `overages.${limitKey}`;

  const existing = await TenantMetrics.findOne({ tenantId }).lean();
  const previous = existing?.overages?.[limitKey];
  const isNewMonth = !previous || previous.monthKey !== monthKey;

  await TenantMetrics.updateOne(
    { tenantId },
    {
      $set: {
        [`${field}.monthKey`]: monthKey,
        [`${field}.count`]: isNewMonth ? 1 : (Number(previous.count) || 0) + 1,
        [`${field}.lastAt`]: at,
      },
      $setOnInsert: { tenantId },
    },
    { upsert: true }
  );

  if (isNewMonth) {
    await PlatformEvent.create({
      tenantId,
      eventType: 'usage.overage',
      payload: { limitKey, limit, current, monthKey },
      occurredAt: at,
    }).catch((err) => console.error('[limits] failed to record overage event:', err.message));
  }

  console.warn(
    `[limits] Soft limit exceeded for tenant ${tenantId}: ${limitKey} ${current}/${limit} — allowing with overage`
  );
}

/**
 * Assert the tenant can store `additional` more repositories.
 * When `currentCount` is omitted, counts from the tenant DB.
 */
async function assertRepoCapacity(tenantId, options = {}) {
  const { additional = 1, currentCount } = options;
  const limits = await resolveLimitContext(tenantId, options);

  if (!limits.active) {
    throw createError(403, 'Your organization license is not active');
  }

  const limit = limits.maxRepos;
  const current =
    currentCount != null ? Number(currentCount) : await countTenantRepos(tenantId);

  if (Number.isFinite(limit) && current + additional > limit) {
    if (limitMode(limits.entitlements, LIMIT_KEYS.MAX_REPOS) === 'soft') {
      await recordOverage(tenantId, LIMIT_KEYS.MAX_REPOS, { limit, current });
    } else {
      throw limitExceededError(LIMIT_KEYS.MAX_REPOS, limit, current);
    }
  }

  return { limit, current, unlimited: !Number.isFinite(limit) };
}

/**
 * Assert the tenant can add one more user (member login / invite).
 *
 * Per-seat plans set `maxUsers` to UNLIMITED: the join always succeeds and the
 * seat is simply counted for billing. Only a genuinely capped plan (e.g. Free)
 * rejects here.
 */
async function assertUserCapacity(tenantId, options = {}) {
  const limits = await resolveLimitContext(tenantId, options);

  if (!limits.active) {
    throw createError(403, 'Your organization license is not active');
  }

  const limit = limits.maxUsers;
  const current = await countTenantUsers(tenantId);
  const verdict = evaluateLimit(LIMIT_KEYS.MAX_USERS, {
    current,
    limit,
    entitlements: limits.entitlements,
  });

  if (verdict.exceeded) {
    if (verdict.mode === 'soft') {
      await recordOverage(tenantId, LIMIT_KEYS.MAX_USERS, { limit, current });
    } else {
      throw limitExceededError(LIMIT_KEYS.MAX_USERS, limit, current);
    }
  }

  return { limit, current, unlimited: !Number.isFinite(limit) };
}

/**
 * Assert the tenant can trigger another scan.
 *
 * Checks the daily ceiling and the monthly ceiling. A limit in 'soft' mode lets
 * the scan through and records an overage instead of rejecting — that is how a
 * plan sold as "600/day soft limit with overages" behaves.
 */
async function assertScanCapacity(tenantId, options = {}) {
  const limits = await resolveLimitContext(tenantId, options);

  if (!limits.active) {
    throw createError(403, 'Your organization license is not active');
  }

  const [{ count: monthCount }, { count: dayCount }] = await Promise.all([
    getMonthlyScanUsage(tenantId),
    getDailyScanUsage(tenantId),
  ]);

  const checks = [
    evaluateLimit(LIMIT_KEYS.MAX_SCANS_PER_DAY, {
      current: dayCount,
      limit: limits.maxScansPerDay,
      entitlements: limits.entitlements,
    }),
    evaluateLimit(LIMIT_KEYS.MAX_SCANS_PER_MONTH, {
      current: monthCount,
      limit: limits.maxScansPerMonth,
      entitlements: limits.entitlements,
    }),
  ];

  const keyFor = [LIMIT_KEYS.MAX_SCANS_PER_DAY, LIMIT_KEYS.MAX_SCANS_PER_MONTH];

  // Reject on the first hard breach; only then fall back to recording overages,
  // so a hard monthly cap still stops a tenant whose daily limit is soft.
  for (let i = 0; i < checks.length; i += 1) {
    const check = checks[i];
    if (check.exceeded && check.mode === 'hard') {
      throw limitExceededError(keyFor[i], check.limit, check.current);
    }
  }

  for (let i = 0; i < checks.length; i += 1) {
    const check = checks[i];
    if (check.exceeded && check.mode === 'soft') {
      await recordOverage(tenantId, keyFor[i], {
        limit: check.limit,
        current: check.current,
      });
    }
  }

  return {
    limit: limits.maxScansPerMonth,
    current: monthCount,
    daily: { limit: limits.maxScansPerDay, current: dayCount },
  };
}

const SCAN_WINDOW_DAYS = 30;

/** UTC day key, matching the granularity of the rolling window. */
function currentDayKey(date = new Date()) {
  return date.toISOString().slice(0, 10); // YYYY-MM-DD
}

/** The oldest day key still inside the rolling window. */
function windowStartKey(date = new Date()) {
  const start = new Date(date);
  start.setUTCDate(start.getUTCDate() - (SCAN_WINDOW_DAYS - 1));
  return currentDayKey(start);
}

/**
 * Drop buckets that have aged out and add one scan to today's (MT-12.1).
 *
 * Keeping the window as day buckets means `scanCount30d` decays on its own the
 * next time a tenant scans — no cron job to schedule, monitor, or forget.
 *
 * @returns {{ scanDaily: Array<{date: string, count: number}>, scanCount30d: number }}
 */
function advanceScanWindow(existingDaily, { at = new Date(), increment = 1 } = {}) {
  const today = currentDayKey(at);
  const cutoff = windowStartKey(at);

  const buckets = (Array.isArray(existingDaily) ? existingDaily : [])
    .filter((b) => b && typeof b.date === 'string' && b.date >= cutoff)
    .map((b) => ({ date: b.date, count: Number(b.count) || 0 }));

  const todayBucket = buckets.find((b) => b.date === today);
  if (todayBucket) {
    todayBucket.count += increment;
  } else if (increment > 0) {
    buckets.push({ date: today, count: increment });
  }

  buckets.sort((a, b) => a.date.localeCompare(b.date));

  return {
    scanDaily: buckets,
    scanCount30d: buckets.reduce((sum, b) => sum + b.count, 0),
  };
}

/** Record a scan against the monthly quota and the rolling 30-day window. */
async function recordScanTriggered(tenantId, { at = new Date() } = {}) {
  const { TenantMetrics } = getControlModels();
  const monthKey = currentMonthKey(at);
  const existing = await TenantMetrics.findOne({ tenantId }).lean();

  const { scanDaily, scanCount30d } = advanceScanWindow(existing?.scanDaily, { at });

  if (!existing) {
    await TenantMetrics.create({
      tenantId,
      scanCountThisMonth: 1,
      scanMonthKey: monthKey,
      scanDaily,
      scanCount30d,
      lastScanAt: at,
    });
    return;
  }

  const resetMonth = existing.scanMonthKey !== monthKey;
  const update = {
    $set: {
      scanMonthKey: monthKey,
      scanDaily,
      scanCount30d,
      lastScanAt: at,
    },
  };

  // $inc for the quota counter so concurrent triggers cannot lose an increment —
  // this is the number maxScansPerMonth is enforced against.
  if (resetMonth) {
    update.$set.scanCountThisMonth = 1;
  } else {
    update.$inc = { scanCountThisMonth: 1 };
  }

  await TenantMetrics.updateOne({ tenantId }, update);
}

/**
 * Re-trim a tenant's window without recording a scan. Lets a reporting read show
 * a decayed figure for a tenant that has not scanned recently.
 */
async function refreshScanWindow(tenantId, { at = new Date() } = {}) {
  const { TenantMetrics } = getControlModels();
  const existing = await TenantMetrics.findOne({ tenantId }).lean();
  if (!existing) return { scanCount30d: 0 };

  const { scanDaily, scanCount30d } = advanceScanWindow(existing.scanDaily, {
    at,
    increment: 0,
  });

  if (scanCount30d !== (Number(existing.scanCount30d) || 0)) {
    await TenantMetrics.updateOne({ tenantId }, { $set: { scanDaily, scanCount30d } });
  }

  return { scanCount30d };
}

/** Refresh control-plane usage rollups from tenant DB counts. */
async function syncUsageMetrics(tenantId) {
  const { TenantMetrics } = getControlModels();
  const [userCount, repoCount] = await Promise.all([
    countTenantUsers(tenantId),
    countTenantRepos(tenantId),
  ]);

  await TenantMetrics.updateOne(
    { tenantId },
    {
      $set: { userCount, repoCount },
      $setOnInsert: { tenantId },
    },
    { upsert: true }
  );

  return { userCount, repoCount };
}

module.exports = {
  LIMIT_KEYS,
  SCAN_WINDOW_DAYS,
  currentMonthKey,
  currentDayKey,
  windowStartKey,
  advanceScanWindow,
  refreshScanWindow,
  readLimit,
  readPlanLimit,
  LIMIT_ABSENT_DEFAULTS,
  resolveTenantLimits,
  countTenantUsers,
  countTenantRepos,
  getMonthlyScanUsage,
  getDailyScanUsage,
  evaluateLimit,
  recordOverage,
  capReposToLimit,
  assertRepoCapacity,
  assertUserCapacity,
  assertScanCapacity,
  recordScanTriggered,
  syncUsageMetrics,
  limitExceededError,
};
