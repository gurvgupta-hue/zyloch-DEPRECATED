const { describe, it, before } = require('node:test');
const assert = require('node:assert/strict');

describe('jwt session payload', () => {
  let jwtUtils;

  before(() => {
    process.env.APP_JWT_SECRET = process.env.APP_JWT_SECRET || 'test-jwt-secret-for-unit-tests';
    process.env.APP_ENCRYPTION_SECRET =
      process.env.APP_ENCRYPTION_SECRET || 'test-encryption-secret-32chars!!';
    jwtUtils = require('../utils/jwt');
  });

  it('buildSessionPayload includes tenantId and role for org login', () => {
    const payload = jwtUtils.buildSessionPayload({
      userId: '674a1b2c3d4e5f6789012345',
      tenantId: '674a1b2c3d4e5f6789012345',
      email: 'admin@example.com',
      provider: 'github',
      role: 'admin',
    });

    assert.equal(payload.userId, '674a1b2c3d4e5f6789012345');
    assert.equal(payload.tenantId, '674a1b2c3d4e5f6789012345');
    assert.equal(payload.role, 'admin');
    assert.equal(payload.provider, 'github');
  });

  it('buildSessionPayload omits tenantId for pre-org flows', () => {
    const payload = jwtUtils.buildSessionPayload({
      userId: '674a1b2c3d4e5f6789012345',
      email: 'user@example.com',
      provider: 'github',
    });

    assert.equal(payload.tenantId, undefined);
    assert.equal(payload.role, undefined);
  });

  it('buildSessionPayload rejects invalid role', () => {
    assert.throws(
      () =>
        jwtUtils.buildSessionPayload({
          userId: '1',
          tenantId: '1',
          email: 'a@b.com',
          provider: 'github',
          role: 'superuser',
        }),
      /Invalid role/
    );
  });

  it('signSession and verifySession round-trip tenantId and role', () => {
    const payload = jwtUtils.buildSessionPayload({
      userId: '674a1b2c3d4e5f6789012346',
      tenantId: '674a1b2c3d4e5f6789012345',
      email: 'member@example.com',
      provider: 'google',
      role: 'member',
    });

    const token = jwtUtils.signSession(payload);
    const decoded = jwtUtils.verifySession(token);

    assert.equal(decoded.userId, payload.userId);
    assert.equal(decoded.tenantId, payload.tenantId);
    assert.equal(decoded.role, 'member');
    assert.equal(decoded.email, payload.email);
    assert.equal(decoded.provider, 'google');
  });

  it('sessionClaimsStale is true when role missing or changed', () => {
    assert.equal(jwtUtils.sessionClaimsStale({ role: 'admin' }, { role: 'admin' }), false);
    assert.equal(jwtUtils.sessionClaimsStale({ role: 'member' }, { role: 'admin' }), true);
    assert.equal(jwtUtils.sessionClaimsStale({}, { role: 'member' }), true);
    assert.equal(jwtUtils.sessionClaimsStale({ role: null }, { role: 'member' }), true);
  });

  it('VALID_ROLES lists admin and member', () => {
    assert.deepEqual(jwtUtils.VALID_ROLES, ['admin', 'member']);
  });
});
