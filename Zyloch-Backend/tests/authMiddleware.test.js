const { describe, it, before } = require('node:test');
const assert = require('node:assert/strict');

describe('auth middleware context', () => {
  let buildAuthContext;

  before(() => {
    process.env.APP_JWT_SECRET = process.env.APP_JWT_SECRET || 'test-jwt-secret-for-unit-tests';
    process.env.APP_ENCRYPTION_SECRET =
      process.env.APP_ENCRYPTION_SECRET || 'test-encryption-secret-32chars!!';
    buildAuthContext = require('../middleware/auth').buildAuthContext;
  });

  it('buildAuthContext sets req.tenant shape from JWT', () => {
    const ctx = buildAuthContext({
      session: { role: 'admin' },
      user: { role: 'member' },
      tenantId: '674a1b2c3d4e5f6789012345',
    });

    assert.deepEqual(ctx.tenant, {
      id: '674a1b2c3d4e5f6789012345',
      role: 'admin',
    });
    assert.equal(ctx.userFields.organizationId, '674a1b2c3d4e5f6789012345');
    assert.equal(ctx.userFields.tenantId, '674a1b2c3d4e5f6789012345');
    assert.equal(ctx.userFields.role, 'admin');
  });

  it('buildAuthContext falls back to DB role when JWT role absent', () => {
    const ctx = buildAuthContext({
      session: {},
      user: { role: 'member' },
      tenantId: '674a1b2c3d4e5f6789012346',
    });

    assert.equal(ctx.tenant.role, 'member');
    assert.equal(ctx.userFields.role, 'member');
  });

  it('organizationId equals tenant id string', () => {
    const ctx = buildAuthContext({
      session: { role: 'member' },
      user: { role: 'member' },
      tenantId: 'abc123',
    });

    assert.equal(ctx.userFields.organizationId, ctx.tenant.id);
  });
});
