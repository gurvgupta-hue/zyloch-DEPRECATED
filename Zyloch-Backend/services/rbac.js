/**
 * Role-based access control (KAN-55 / Phase 5).
 *
 * Zyloch uses **role-only** RBAC: a tenant user is either `admin` or `member`.
 * There is no per-user permission grant store — see
 * docs/multi-tenant/ADR-001-rbac-role-only.md for the decision record.
 *
 * Capabilities below are named route groups, not persisted entities. They exist
 * so the backend route guards and the frontend UI gates read from one table and
 * cannot drift (a member must never see a control that always 403s).
 */

const ROLES = Object.freeze({ ADMIN: 'admin', MEMBER: 'member' });

const ALL_ROLES = Object.freeze([ROLES.ADMIN, ROLES.MEMBER]);
const ADMIN_ONLY = Object.freeze([ROLES.ADMIN]);

/**
 * capability -> roles allowed.
 * `admin` is a strict superset of `member`; there is no separate bypass path.
 */
const CAPABILITIES = Object.freeze({
  'organization.read': ALL_ROLES,
  'organization.settings.write': ADMIN_ONLY,
  'organization.oauth.write': ADMIN_ONLY,

  'members.read': ALL_ROLES,
  'members.manage': ADMIN_ONLY,

  'license.read': ALL_ROLES,

  'installations.read': ALL_ROLES,

  'repositories.read': ALL_ROLES,
  'repositories.delete': ADMIN_ONLY,
  // Choosing which repositories an over-limit installation monitors is a
  // plan-shaped decision (it decides what the tenant pays to cover), so it sits
  // with the admin who installed the App rather than with every member.
  'repositories.selection.write': ADMIN_ONLY,

  'scans.read': ALL_ROLES,
  'scans.trigger': ALL_ROLES,
  // AI autofix. Same audience as scans.trigger: main shipped these with no role
  // restriction, so gating them to admins would remove access members already had.
  'scans.autofix': ALL_ROLES,
  'scans.autofix.pr': ALL_ROLES,

  'summary.read': ALL_ROLES,
  'summary.refresh': ALL_ROLES,
});

const CAPABILITY_KEYS = Object.freeze(Object.keys(CAPABILITIES));

/** True when the capability exists and the role is allowed to use it. */
function can(role, capability) {
  const allowed = CAPABILITIES[capability];
  if (!allowed) return false;
  return allowed.includes(role);
}

/** True when the capability is restricted to admins (used for error copy). */
function isAdminOnly(capability) {
  const allowed = CAPABILITIES[capability];
  return Array.isArray(allowed) && !allowed.includes(ROLES.MEMBER);
}

/**
 * Full capability map for a role, e.g. `{ 'members.manage': false, ... }`.
 * Served to the frontend so UI gates mirror backend guards exactly.
 */
function capabilitiesFor(role) {
  return CAPABILITY_KEYS.reduce((acc, capability) => {
    acc[capability] = can(role, capability);
    return acc;
  }, {});
}

module.exports = {
  ROLES,
  CAPABILITIES,
  CAPABILITY_KEYS,
  can,
  isAdminOnly,
  capabilitiesFor,
};
