const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const {
  ROLES,
  CAPABILITY_KEYS,
  can,
  isAdminOnly,
  capabilitiesFor,
} = require('../services/rbac');

const ADMIN_ONLY_CAPABILITIES = [
  'organization.settings.write',
  'organization.oauth.write',
  'members.manage',
  'repositories.delete',
];

const MEMBER_CAPABILITIES = [
  'organization.read',
  'members.read',
  'license.read',
  'installations.read',
  'repositories.read',
  'scans.read',
  'scans.trigger',
  'summary.refresh',
];

describe('KAN-56/57 rbac capability map', () => {
  it('exposes exactly the admin and member roles', () => {
    assert.deepEqual(ROLES, { ADMIN: 'admin', MEMBER: 'member' });
  });

  it('grants admin every capability (admin is a superset of member)', () => {
    for (const capability of CAPABILITY_KEYS) {
      assert.equal(can(ROLES.ADMIN, capability), true, `admin denied ${capability}`);
    }
  });

  it('denies member every admin-only capability', () => {
    for (const capability of ADMIN_ONLY_CAPABILITIES) {
      assert.equal(can(ROLES.MEMBER, capability), false, `member allowed ${capability}`);
      assert.equal(isAdminOnly(capability), true);
    }
  });

  it('allows member the shared read/product capabilities', () => {
    for (const capability of MEMBER_CAPABILITIES) {
      assert.equal(can(ROLES.MEMBER, capability), true, `member denied ${capability}`);
      assert.equal(isAdminOnly(capability), false);
    }
  });

  it('denies unknown capabilities and unknown roles', () => {
    assert.equal(can(ROLES.ADMIN, 'not.a.capability'), false);
    assert.equal(can('superadmin', 'organization.read'), false);
    assert.equal(can(undefined, 'organization.read'), false);
  });

  it('capabilitiesFor returns a complete boolean map per role', () => {
    const adminMap = capabilitiesFor(ROLES.ADMIN);
    const memberMap = capabilitiesFor(ROLES.MEMBER);

    assert.deepEqual(Object.keys(adminMap).sort(), [...CAPABILITY_KEYS].sort());
    assert.deepEqual(Object.keys(memberMap).sort(), [...CAPABILITY_KEYS].sort());
    assert.equal(Object.values(adminMap).every((v) => v === true), true);
    assert.equal(memberMap['members.manage'], false);
    assert.equal(memberMap['scans.trigger'], true);
  });

  it('capabilitiesFor an unknown role grants nothing', () => {
    const map = capabilitiesFor('ghost');
    assert.equal(Object.values(map).some(Boolean), false);
  });
});

describe('KAN-57 route guards use the capability map', () => {
  it('admin-only routes are wired with admin-only capabilities', () => {
    const requireCapability = require('../middleware/requireCapability');
    // Wiring a route with an admin-only capability must reject members.
    const guard = requireCapability('repositories.delete');
    let denied;
    guard({ user: { role: 'member' } }, {}, (err) => {
      denied = err;
    });
    assert.equal(denied.statusCode, 403);
  });
});
