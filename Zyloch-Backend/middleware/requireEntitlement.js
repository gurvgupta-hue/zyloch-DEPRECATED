const createError = require('../utils/createError');
const { hasFeature, hasScanner } = require('../services/licenseEntitlements');
const {
  assertRepoCapacity,
  assertUserCapacity,
  assertScanCapacity,
} = require('../services/licenseLimits');

/**
 * Require an active license with a specific feature key (plan-tier gating).
 * Must run after auth middleware (uses req.license).
 */
function requireFeature(featureKey) {
  return (req, res, next) => {
    const license = req.license;
    if (!license?.active) {
      return next(createError(403, 'Your organization license is not active'));
    }
    if (!hasFeature(license.entitlements, featureKey)) {
      return next(createError(403, `Feature not included in your plan: ${featureKey}`));
    }
    return next();
  };
}

/** Require an entitled scanner type. */
function requireScanner(scannerKey) {
  return (req, res, next) => {
    const license = req.license;
    if (!license?.active) {
      return next(createError(403, 'Your organization license is not active'));
    }
    if (!hasScanner(license.entitlements, scannerKey)) {
      return next(createError(403, `Scanner not included in your plan: ${scannerKey}`));
    }
    return next();
  };
}

/** Require active license only (limits come from DB plan entitlements). */
function requireActiveLicense(req, res, next) {
  if (!req.license?.active) {
    return next(createError(403, 'Your organization license is not active'));
  }
  return next();
}

/**
 * Require headroom under a plan limit.
 * @param {'maxRepos'|'maxUsers'|'maxScansPerMonth'} limitKey
 */
function requireLimit(limitKey) {
  return async (req, res, next) => {
    try {
      const options = {
        entitlements: req.license?.entitlements,
        active: req.license?.active,
      };
      if (limitKey === 'maxRepos') {
        await assertRepoCapacity(req.tenantId, options);
      } else if (limitKey === 'maxUsers') {
        await assertUserCapacity(req.tenantId, options);
      } else if (limitKey === 'maxScansPerMonth') {
        await assertScanCapacity(req.tenantId, options);
      } else {
        return next(createError(500, `Unknown license limit key: ${limitKey}`));
      }
      return next();
    } catch (err) {
      return next(err);
    }
  };
}

module.exports = {
  requireFeature,
  requireScanner,
  requireActiveLicense,
  requireLimit,
};
