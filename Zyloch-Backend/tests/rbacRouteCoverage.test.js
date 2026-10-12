const fs = require('fs');
const path = require('path');
const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const { CAPABILITIES, CAPABILITY_KEYS, capabilitiesFor, can } = require('../services/rbac');

const ROUTES_DIR = path.resolve(__dirname, '../routes');

/** Every capability string referenced by a `requireCapability(...)` call. */
function capabilitiesUsedInRoutes() {
  const used = new Map(); // capability -> [files]
  for (const file of fs.readdirSync(ROUTES_DIR).filter((f) => f.endsWith('.js'))) {
    const source = fs.readFileSync(path.join(ROUTES_DIR, file), 'utf8');
    for (const match of source.matchAll(/requireCapability\(\s*['"]([^'"]+)['"]\s*\)/g)) {
      const list = used.get(match[1]) || [];
      list.push(file);
      used.set(match[1], list);
    }
  }
  return used;
}

/**
 * MT-10.1: the capability table and the route guards must not drift.
 *
 * Previously the permissive (`ALL_ROLES`) capabilities had no guard on their
 * routes. That was harmless while both roles were allowed, but the day someone
 * tightened one of those entries to admin-only the table would have silently
 * disagreed with what the routes actually enforce.
 */
describe('MT-10.1 RBAC table and route guards stay in sync', () => {
  const used = capabilitiesUsedInRoutes();

  it('every capability in the table is enforced on at least one route', () => {
    const unused = CAPABILITY_KEYS.filter((key) => !used.has(key));
    assert.deepEqual(
      unused,
      [],
      `capabilities declared but never enforced: ${unused.join(', ')}`
    );
  });

  it('every capability referenced by a route exists in the table', () => {
    const unknown = [...used.keys()].filter((key) => !CAPABILITIES[key]);
    assert.deepEqual(
      unknown,
      [],
      `routes reference capabilities missing from rbac.js: ${unknown.join(', ')}`
    );
  });

  it('requireCapability rejects an unknown capability at load time', () => {
    const requireCapability = require('../middleware/requireCapability');
    assert.throws(() => requireCapability('not.a.capability'), /Unknown RBAC capability/);
  });
});

describe('MT-10 capability semantics', () => {
  it('admin is a strict superset of member', () => {
    const admin = capabilitiesFor('admin');
    const member = capabilitiesFor('member');
    for (const key of CAPABILITY_KEYS) {
      if (member[key]) {
        assert.equal(admin[key], true, `admin must retain ${key}`);
      }
    }
  });

  it('an unknown role gets nothing', () => {
    const nobody = capabilitiesFor('auditor');
    assert.ok(CAPABILITY_KEYS.every((key) => nobody[key] === false));
    assert.equal(can(undefined, 'organization.read'), false);
    assert.equal(can(null, 'members.manage'), false);
  });

  it('write capabilities remain admin-only', () => {
    for (const key of [
      'organization.settings.write',
      'organization.oauth.write',
      'members.manage',
      'repositories.delete',
    ]) {
      assert.equal(can('member', key), false, `${key} must not be granted to member`);
      assert.equal(can('admin', key), true, `${key} must be granted to admin`);
    }
  });
});
