const createError = require('../utils/createError');
const { can, isAdminOnly, CAPABILITIES } = require('../services/rbac');

/**
 * Guard a route with a capability from services/rbac.js.
 * Run after auth (needs req.user.role) and tenantGuard.
 *
 * Denied requests return 403 — the same status cross-tenant access returns, so
 * the frontend never has to distinguish "wrong org" from "wrong role".
 *
 * @param {string} capability key present in rbac CAPABILITIES
 */
function requireCapability(capability) {
  if (!CAPABILITIES[capability]) {
    throw new Error(`Unknown RBAC capability: ${capability}`);
  }

  return function capabilityGuard(req, res, next) {
    const role = req.user?.role;

    if (!can(role, capability)) {
      const message = isAdminOnly(capability)
        ? 'Only organization admin can perform this action'
        : 'You do not have permission to perform this action';
      return next(createError(403, message));
    }

    return next();
  };
}

module.exports = requireCapability;
