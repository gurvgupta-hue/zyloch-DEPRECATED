const createError = require('../utils/createError');
const { getControlModels } = require('../db/controlModels');
const {
  countTenantUsers,
  countTenantRepos,
  getMonthlyScanUsage,
  getDailyScanUsage,
} = require('../services/licenseLimits');
const {
  resolveTenantEntitlements,
  presentLimit,
} = require('../services/licenseEntitlements');

/**
 * GET /api/organization/license
 * Tenant-facing read of the 1:1 control-plane tenant_licenses row.
 * Platform admins create/update licenses in zyloch-platform-console (KAN-43).
 */
async function getLicense(req, res, next) {
  try {
    const { TenantLicense } = getControlModels();
    const licenseDoc = await TenantLicense.findOne({ tenantId: req.tenantId }).lean();
    if (!licenseDoc) {
      return next(createError(404, 'No license found for this organization'));
    }

    const resolved = req.license || (await resolveTenantEntitlements(req.tenantId));
    const [userCount, repoCount, scanUsage, dailyUsage] = await Promise.all([
      countTenantUsers(req.tenantId),
      countTenantRepos(req.tenantId),
      getMonthlyScanUsage(req.tenantId),
      getDailyScanUsage(req.tenantId),
    ]);

    const entitlements = resolved.entitlements || {};
    // `null` == unlimited on the wire; a per-seat plan has no seat ceiling.
    const maxUsers = presentLimit(entitlements.maxUsers);
    const overUserLimit = maxUsers != null && maxUsers > 0 && userCount >= maxUsers;

    res.json({
      success: true,
      license: {
        tenantId: String(req.tenantId),
        planId: licenseDoc.planId,
        planName: resolved.plan?.name || null,
        status: licenseDoc.status,
        active: !!resolved.active,
        startsAt: licenseDoc.startsAt,
        expiresAt: licenseDoc.expiresAt,
        entitlements,
        usage: {
          users: { current: userCount, max: maxUsers },
          repos: { current: repoCount, max: presentLimit(entitlements.maxRepos) },
          scansThisMonth: {
            current: scanUsage.count,
            max: presentLimit(entitlements.maxScansPerMonth),
            monthKey: scanUsage.monthKey,
          },
          scansToday: {
            current: dailyUsage.count,
            max: presentLimit(entitlements.maxScansPerDay),
            dayKey: dailyUsage.dayKey,
          },
        },
        overLimit: { users: overUserLimit },
      },
    });
  } catch (err) {
    next(err);
  }
}

module.exports = { getLicense };
