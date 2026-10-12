const mongoose = require('mongoose');

const TenantMetricsSchema = new mongoose.Schema(
  {
    tenantId: { type: mongoose.Schema.Types.ObjectId, required: true, unique: true },
    userCount: { type: Number, default: 0 },
    installationCount: { type: Number, default: 0 },
    repoCount: { type: Number, default: 0 },
    teamCount: { type: Number, default: 0 },
    /**
     * Rolling 30-day scan total, derived from `scanDaily` on every write.
     * Never incremented on its own — it used to be, which made it a lifetime
     * total that only ever grew (MT-12.1).
     */
    scanCount30d: { type: Number, default: 0 },
    /**
     * Per-day scan buckets backing `scanCount30d`. Entries older than the window
     * are dropped whenever a scan is recorded, so the metric decays without a
     * separate scheduled job.
     */
    scanDaily: {
      type: [
        {
          _id: false,
          date: { type: String, required: true }, // YYYY-MM-DD (UTC)
          count: { type: Number, default: 0 },
        },
      ],
      default: [],
    },
    /** Calendar-month scan counter used for maxScansPerMonth enforcement. */
    scanCountThisMonth: { type: Number, default: 0 },
    /** YYYY-MM key for scanCountThisMonth; resets when the month rolls over. */
    scanMonthKey: { type: String, default: null },
    securityEventCount: { type: Number, default: 0 },
    /**
     * Soft-limit breaches, counted per calendar month per limit key, e.g.
     * `{ maxScansPerDay: { monthKey: '2026-08', count: 12, lastAt: Date } }`.
     * Written only for limits a plan marks 'soft'; billing reads this to invoice
     * overages.
     */
    overages: { type: mongoose.Schema.Types.Mixed, default: {} },
    lastScanAt: { type: Date, default: null },
    lastLoginAt: { type: Date, default: null },
  },
  { timestamps: { createdAt: false, updatedAt: true }, collection: 'tenant_metrics' }
);

module.exports = {
  schema: TenantMetricsSchema,
  modelName: 'TenantMetrics',
  collection: 'tenant_metrics',
};
