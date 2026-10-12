import {
  estimateSyncWindow,
  estimateRemaining,
  syncEtaLabel,
  formatDuration,
} from "@/lib/syncEstimate";

describe("sync estimate", () => {
  it("bands the expected window by repository volume", () => {
    expect(estimateSyncWindow(12).label).toBe("a few minutes");
    expect(estimateSyncWindow(400).label).toBe("about 10–30 minutes");
    // The plan boundaries customers actually hit.
    expect(estimateSyncWindow(2000).label).toBe("about 30 minutes to 2 hours");
    expect(estimateSyncWindow(5000).label).toBe("about 2 to 6 hours");
    expect(estimateSyncWindow(21430).label).toBe("up to 24 hours");
  });

  it("treats a missing count as the smallest band rather than throwing", () => {
    expect(estimateSyncWindow(undefined).label).toBe("a few minutes");
    expect(estimateSyncWindow(null).repoCount).toBe(0);
  });

  it("formats durations compactly", () => {
    expect(formatDuration(45_000)).toBe("45s");
    expect(formatDuration(90_000)).toBe("1m");
    expect(formatDuration(3 * 3_600_000)).toBe("3h");
    expect(formatDuration(3 * 3_600_000 + 14 * 60_000)).toBe("3h 14m");
    expect(formatDuration(26 * 3_600_000)).toBe("1d 2h");
  });

  it("extrapolates the remaining time once progress is meaningful", () => {
    const startedAt = new Date("2026-09-16T00:00:00Z").toISOString();
    const now = new Date("2026-09-16T01:00:00Z").getTime(); // one hour in

    // 25% done after an hour → about three hours left.
    expect(estimateRemaining({ progress: 25, startedAt, now })).toBe(3 * 3_600_000);
  });

  it("refuses to extrapolate from noise", () => {
    const startedAt = new Date("2026-09-16T00:00:00Z").toISOString();
    const now = new Date("2026-09-16T00:00:03Z").getTime();

    // 3% in the first seconds would promise a wildly wrong number.
    expect(estimateRemaining({ progress: 3, startedAt, now })).toBeNull();
    expect(estimateRemaining({ progress: 50, startedAt: null, now })).toBeNull();
    expect(estimateRemaining({ progress: 100, startedAt, now })).toBeNull();
  });

  it("falls back to the volume band until the estimate is trustworthy", () => {
    const startedAt = new Date("2026-09-16T00:00:00Z").toISOString();
    const early = new Date("2026-09-16T00:00:02Z").getTime();
    const later = new Date("2026-09-16T02:00:00Z").getTime();

    expect(syncEtaLabel({ repoCount: 21430, progress: 1, startedAt, now: early })).toBe(
      "This usually takes up to 24 hours"
    );
    expect(syncEtaLabel({ repoCount: 21430, progress: 50, startedAt, now: later })).toBe(
      "about 2h left"
    );
  });
});
