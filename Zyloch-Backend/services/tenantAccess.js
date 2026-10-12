/**
 * Per-request tenant access resolution (MT-05.4).
 *
 * The control plane already recorded whether an organization is active
 * (`organizations.isActive` / `provisionStatus`), but nothing on the request path
 * ever read it — so suspending a tenant locked nobody out. This resolves that
 * state alongside the license so `middleware/auth.js` can act on both.
 *
 * The two control-plane reads run in parallel, so adding the organization lookup
 * costs no extra round-trip latency versus resolving entitlements alone.
 */

const { getControlModels } = require('../db/controlModels');
const { resolveTenantEntitlements } = require('./licenseEntitlements');

/**
 * Provision states that must not serve requests.
 *
 * Deliberately a DENY list rather than an allow list of `['active']`: it makes
 * suspension effective (the actual defect) without risking a lockout for any
 * organization document whose `provisionStatus` predates the field or was
 * written outside `provisionTenant`.
 */
const BLOCKED_PROVISION_STATUSES = Object.freeze(
  new Set(['suspended', 'offboarding', 'offboarded'])
);

const TENANT_ACCESS_ERRORS = Object.freeze({
  ORG_NOT_FOUND: 'tenant_not_found',
  ORG_INACTIVE: 'tenant_inactive',
  ORG_SUSPENDED: 'tenant_suspended',
});

/**
 * Decide whether an organization document may serve requests.
 * @returns {{ allowed: boolean, code?: string, message?: string }}
 */
function evaluateTenantStanding(organization) {
  if (!organization) {
    return {
      allowed: false,
      code: TENANT_ACCESS_ERRORS.ORG_NOT_FOUND,
      message: 'Your organization no longer exists. Please sign in again.',
    };
  }

  if (organization.isActive === false) {
    return {
      allowed: false,
      code: TENANT_ACCESS_ERRORS.ORG_INACTIVE,
      message: 'Your organization has been deactivated. Contact Zyloch support.',
    };
  }

  if (BLOCKED_PROVISION_STATUSES.has(organization.provisionStatus)) {
    return {
      allowed: false,
      code: TENANT_ACCESS_ERRORS.ORG_SUSPENDED,
      message: `Your organization is currently ${organization.provisionStatus}. Contact Zyloch support.`,
    };
  }

  return { allowed: true };
}

/**
 * Resolve an organization's standing and effective entitlements in one step.
 * @returns {Promise<{ organization: object|null, license: object, standing: object }>}
 */
async function resolveTenantAccess(tenantId, deps = {}) {
  const getControl = deps.getControlModels || getControlModels;
  const resolveEntitlements = deps.resolveTenantEntitlements || resolveTenantEntitlements;

  const { Organization } = getControl();

  const [organization, license] = await Promise.all([
    Organization.findById(tenantId).select('name isActive provisionStatus').lean(),
    resolveEntitlements(tenantId),
  ]);

  return {
    organization: organization || null,
    license,
    standing: evaluateTenantStanding(organization),
  };
}

module.exports = {
  BLOCKED_PROVISION_STATUSES,
  TENANT_ACCESS_ERRORS,
  evaluateTenantStanding,
  resolveTenantAccess,
};
