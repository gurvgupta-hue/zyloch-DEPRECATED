const mongoose = require('mongoose');
const { EntitlementsSchema } = require('./entitlementsSchema');

const LicensePlanSchema = new mongoose.Schema(
  {
    planId: { type: String, required: true, unique: true },
    name: { type: String, required: true },
    description: { type: String, default: '' },
    entitlements: { type: EntitlementsSchema, default: () => ({}) },
    /**
     * List price, for display only — nothing here bills anyone.
     *
     * Both rates are per seat per month; `perSeatAnnualMonthly` is the cheaper
     * monthly rate a customer gets for committing annually, not a yearly total.
     * Absent on plans that are quoted rather than listed (Enterprise).
     */
    pricing: {
      currency: { type: String, default: 'USD' },
      perSeatMonthly: { type: Number, default: null },
      perSeatAnnualMonthly: { type: Number, default: null },
    },
    isActive: { type: Boolean, default: true },
  },
  { timestamps: true, collection: 'license_plans' }
);

module.exports = { schema: LicensePlanSchema, modelName: 'LicensePlan', collection: 'license_plans' };
