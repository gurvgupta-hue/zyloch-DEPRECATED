const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const tenantGuard = require('../middleware/tenantGuard');
const requireCapability = require('../middleware/requireCapability');

function runMiddleware(middleware, req) {
  return new Promise((resolve) => {
    let statusCode = null;
    const res = {};
    const next = (err) => {
      resolve({ err, statusCode: err?.statusCode ?? statusCode });
    };
    middleware(req, res, next);
  });
}

describe('tenantGuard', () => {
  it('allows request when req.tenant.id is set', async () => {
    const result = await runMiddleware(tenantGuard, {
      tenant: { id: '674a1b2c3d4e5f6789012345', role: 'admin' },
    });
    assert.equal(result.err, undefined);
  });

  it('returns 403 when req.tenant is missing', async () => {
    const result = await runMiddleware(tenantGuard, {});
    assert.equal(result.err.statusCode, 403);
    assert.match(result.err.message, /organization context required/i);
  });

  it('returns 403 when req.tenant.id is empty', async () => {
    const result = await runMiddleware(tenantGuard, { tenant: { role: 'admin' } });
    assert.equal(result.err.statusCode, 403);
  });
});

describe('requireCapability (admin-only capability)', () => {
  const membersManage = requireCapability('members.manage');
  const tenantReq = {
    tenant: { id: '674a1b2c3d4e5f6789012345', role: 'admin' },
  };

  it('allows admin users', async () => {
    const result = await runMiddleware(membersManage, {
      ...tenantReq,
      user: { role: 'admin' },
    });
    assert.equal(result.err, undefined);
  });

  it('returns 403 for member users', async () => {
    const result = await runMiddleware(membersManage, {
      ...tenantReq,
      user: { role: 'member' },
    });
    assert.equal(result.err.statusCode, 403);
    assert.match(result.err.message, /only organization admin/i);
  });

  it('returns 403 when user context is missing', async () => {
    const result = await runMiddleware(membersManage, { ...tenantReq });
    assert.equal(result.err.statusCode, 403);
  });

  it('throws at wiring time for an unknown capability', () => {
    assert.throws(() => requireCapability('does.not.exist'), /Unknown RBAC capability/);
  });
});

describe('requireCapability (shared capability)', () => {
  const scansTrigger = requireCapability('scans.trigger');

  it('allows members', async () => {
    const result = await runMiddleware(scansTrigger, {
      tenant: { id: '674a1b2c3d4e5f6789012345', role: 'member' },
      user: { role: 'member' },
    });
    assert.equal(result.err, undefined);
  });

  it('allows admins', async () => {
    const result = await runMiddleware(scansTrigger, {
      tenant: { id: '674a1b2c3d4e5f6789012345', role: 'admin' },
      user: { role: 'admin' },
    });
    assert.equal(result.err, undefined);
  });

  it('returns 403 for an unknown role', async () => {
    const result = await runMiddleware(scansTrigger, {
      tenant: { id: '674a1b2c3d4e5f6789012345', role: 'viewer' },
      user: { role: 'viewer' },
    });
    assert.equal(result.err.statusCode, 403);
  });
});

describe('tenantGuard + requireCapability chain', () => {
  const oauthWrite = requireCapability('organization.oauth.write');

  it('blocks at tenantGuard before the capability guard when tenant is absent', async () => {
    const tenantResult = await runMiddleware(tenantGuard, {
      user: { role: 'admin' },
    });
    assert.equal(tenantResult.err.statusCode, 403);

    // The capability guard alone does not check tenant; route order is tenantGuard first.
    const adminResult = await runMiddleware(oauthWrite, {
      user: { role: 'admin' },
    });
    assert.equal(adminResult.err, undefined);
  });

  it('allows admin with tenant, denies member with tenant', async () => {
    const base = {
      tenant: { id: '674a1b2c3d4e5f6789012345', role: 'admin' },
    };

    const tenantOk = await runMiddleware(tenantGuard, {
      ...base,
      user: { role: 'member' },
    });
    assert.equal(tenantOk.err, undefined);

    const memberDenied = await runMiddleware(oauthWrite, {
      ...base,
      user: { role: 'member' },
    });
    assert.equal(memberDenied.err.statusCode, 403);

    const adminAllowed = await runMiddleware(oauthWrite, {
      ...base,
      user: { role: 'admin' },
    });
    assert.equal(adminAllowed.err, undefined);
  });
});
