const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const {
  advanceScanWindow,
  currentDayKey,
  windowStartKey,
  SCAN_WINDOW_DAYS,
} = require('../services/licenseLimits');

const at = (iso) => new Date(iso);
const dayOffset = (base, days) => {
  const d = new Date(base);
  d.setUTCDate(d.getUTCDate() + days);
  return d;
};

describe('MT-12.1 rolling 30-day scan window', () => {
  it('starts a bucket for today on the first scan', () => {
    const { scanDaily, scanCount30d } = advanceScanWindow([], { at: at('2026-08-01T10:00:00Z') });
    assert.deepEqual(scanDaily, [{ date: '2026-08-01', count: 1 }]);
    assert.equal(scanCount30d, 1);
  });

  it('accumulates repeat scans on the same day', () => {
    let state = advanceScanWindow([], { at: at('2026-08-01T01:00:00Z') });
    state = advanceScanWindow(state.scanDaily, { at: at('2026-08-01T20:00:00Z') });
    assert.deepEqual(state.scanDaily, [{ date: '2026-08-01', count: 2 }]);
    assert.equal(state.scanCount30d, 2);
  });

  it('sums across days inside the window', () => {
    let daily = [];
    const start = at('2026-07-20T00:00:00Z');
    for (let i = 0; i < 5; i += 1) {
      daily = advanceScanWindow(daily, { at: dayOffset(start, i) }).scanDaily;
    }
    assert.equal(daily.length, 5);
    assert.equal(advanceScanWindow(daily, { at: dayOffset(start, 4), increment: 0 }).scanCount30d, 5);
  });

  it('DECAYS: buckets older than the window are dropped', () => {
    // The original defect: scanCount30d only ever incremented, so it became a
    // lifetime total and "last 30 days" reporting was wrong forever.
    const old = [
      { date: '2026-01-01', count: 500 },
      { date: '2026-06-15', count: 42 },
    ];
    const { scanDaily, scanCount30d } = advanceScanWindow(old, {
      at: at('2026-08-01T00:00:00Z'),
    });
    assert.deepEqual(scanDaily, [{ date: '2026-08-01', count: 1 }]);
    assert.equal(scanCount30d, 1, 'stale buckets must not count');
  });

  it('keeps the oldest day still inside the window and drops the one before it', () => {
    const now = at('2026-08-01T00:00:00Z');
    const oldest = windowStartKey(now);
    const justOutside = currentDayKey(dayOffset(now, -SCAN_WINDOW_DAYS));

    const { scanDaily } = advanceScanWindow(
      [
        { date: justOutside, count: 7 },
        { date: oldest, count: 3 },
      ],
      { at: now, increment: 0 }
    );

    assert.deepEqual(scanDaily.map((b) => b.date), [oldest]);
  });

  it('can re-trim without recording a scan', () => {
    const { scanDaily, scanCount30d } = advanceScanWindow(
      [{ date: '2026-01-01', count: 99 }],
      { at: at('2026-08-01T00:00:00Z'), increment: 0 }
    );
    assert.deepEqual(scanDaily, []);
    assert.equal(scanCount30d, 0);
  });

  it('tolerates missing or malformed bucket data', () => {
    for (const input of [undefined, null, 'nonsense', [null, {}, { date: 5 }]]) {
      const result = advanceScanWindow(input, { at: at('2026-08-01T00:00:00Z') });
      assert.deepEqual(result.scanDaily, [{ date: '2026-08-01', count: 1 }]);
    }
  });

  it('keeps buckets in chronological order', () => {
    const { scanDaily } = advanceScanWindow(
      [
        { date: '2026-07-30', count: 1 },
        { date: '2026-07-25', count: 2 },
      ],
      { at: at('2026-08-01T00:00:00Z') }
    );
    assert.deepEqual(scanDaily.map((b) => b.date), ['2026-07-25', '2026-07-30', '2026-08-01']);
  });

  it('window covers exactly SCAN_WINDOW_DAYS days inclusive', () => {
    const now = at('2026-08-01T00:00:00Z');
    assert.equal(windowStartKey(now), '2026-07-03');
    assert.equal(currentDayKey(now), '2026-08-01');
  });
});
