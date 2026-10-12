const createError = require('../utils/createError');

/**
 * Requires req.tenant.id (set by auth middleware).
 * Use after auth on protected routes that need organization context.
 */
function tenantGuard(req, res, next) {
  if (!req.tenant?.id) {
    return next(createError(403, 'Organization context required.'));
  }
  return next();
}

module.exports = tenantGuard;
