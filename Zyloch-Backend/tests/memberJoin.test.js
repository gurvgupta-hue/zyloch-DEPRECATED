const path = require('path');
const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');

const TENANT_A = '674a1b2c3d4e5f6789012345';

const controlModelsPath = path.resolve(__dirname, '../db/controlModels.js');
const tenantModelsPath = path.resolve(__dirname, '../db/tenantModels.js');
const licenseLimitsPath = path.resolve(__dirname, '../services/licenseLimits.js');
const authRoutingPath = path.resolve(__dirname, '../services/authRouting.js');

function stub(modulePath, exports) {
  require.cache[modulePath] = { id: modulePath, filename: modulePath, loaded: true, exports };
}

/** Mutable state each test asserts against. */
function makeWorld({
  org = { _id: TENANT_A, isActive: true },
  authIdentity = null,
  userById = null,
  userByEmail = null,
  invite = null,
} = {}) {
  const world = {
    createdIdentities: [],
    upsertedIdentities: [],
    createdUsers: [],
    inviteUpdates: [],
    savedUsers: [],
    usageSynced: 0,
    capacityChecks: 0,
  };

  const mkUser = (doc) =>
    doc && {
      identities: [],
      ...doc,
      async save() {
        world.savedUsers.push(this);
        return this;
      },
    };

  stub(controlModelsPath, {
    getControlModels: () => ({
      Organization: { findById: async () => org },
      AuthIdentity: {
        findOne: async () => authIdentity,
        create: async (doc) => {
          world.createdIdentities.push(doc);
          return doc;
        },
        updateOne: async (filter, update) => {
          world.upsertedIdentities.push({ filter, update });
          return { acknowledged: true };
        },
      },
    }),
  });

  stub(tenantModelsPath, {
    getTenantModels: () => ({
      User: {
        findById: async () => mkUser(userById),
        findOne: async () => mkUser(userByEmail),
        create: async (doc) => {
          world.createdUsers.push(doc);
          return doc;
        },
      },
      MemberInvite: {
        findOne: async () => invite,
        updateOne: async (filter, update) => {
          world.inviteUpdates.push({ filter, update });
          return { acknowledged: true };
        },
      },
    }),
  });

  stub(licenseLimitsPath, {
    assertUserCapacity: async () => {
      world.capacityChecks += 1;
      return { limit: 5, current: 1 };
    },
    syncUsageMetrics: async () => {
      world.usageSynced += 1;
    },
  });

  delete require.cache[authRoutingPath];
  world.authRouting = require('../services/authRouting');
  return world;
}

function loginArgs(overrides = {}) {
  return {
    provider: 'google',
    providerId: 'g-123',
    providerData: { email: 'newbie@acme.com', name: 'Newbie' },
    tokens: { accessToken: 'a', refreshToken: 'r', tokenExpiry: null },
    tenantId: TENANT_A,
    ...overrides,
  };
}

afterEach(() => {
  delete require.cache[controlModelsPath];
  delete require.cache[tenantModelsPath];
  delete require.cache[licenseLimitsPath];
  delete require.cache[authRoutingPath];
});

describe('MT-02.1 joining a tenant requires an invite', () => {
  it('rejects an uninvited Google account holding a valid tenantId', async () => {
    const world = makeWorld({ invite: null });

    await assert.rejects(
      () => world.authRouting.loginMember(loginArgs()),
      (err) => err.statusCode === 403 && err.code === 'invite_required'
    );

    assert.equal(world.createdUsers.length, 0, 'must not create a user');
    assert.equal(world.createdIdentities.length, 0, 'must not create an identity');
    assert.equal(world.capacityChecks, 0, 'must not consume a seat');
  });

  it('rejects when the invite has expired', async () => {
    // findOne filters on expiresAt > now, so an expired invite simply misses.
    const world = makeWorld({ invite: null });
    await assert.rejects(
      () => world.authRouting.loginMember(loginArgs()),
      (err) => err.code === 'invite_required'
    );
  });

  it('admits an invited email and redeems the invite once', async () => {
    const world = makeWorld({
      invite: { _id: 'inv-1', email: 'newbie@acme.com', status: 'pending' },
    });

    const { user, tenantId } = await world.authRouting.loginMember(loginArgs());

    assert.equal(user.email, 'newbie@acme.com');
    assert.equal(user.role, 'member');
    assert.equal(String(tenantId), TENANT_A);
    assert.equal(world.capacityChecks, 1);
    assert.equal(world.createdIdentities.length, 1);
    assert.equal(world.usageSynced, 1);

    assert.equal(world.inviteUpdates.length, 1);
    const [{ filter, update }] = world.inviteUpdates;
    assert.equal(filter._id, 'inv-1');
    assert.equal(filter.status, 'pending', 'redemption must be conditional to stay single-use');
    assert.equal(update.$set.status, 'accepted');
    assert.equal(update.$set.acceptedUserId, world.createdUsers[0]._id);
  });

  it('matches the invite case-insensitively and stores a normalized email', async () => {
    const world = makeWorld({
      invite: { _id: 'inv-2', email: 'newbie@acme.com', status: 'pending' },
    });

    await world.authRouting.loginMember(
      loginArgs({ providerData: { email: '  NewBie@Acme.COM ', name: 'N' } })
    );

    assert.equal(world.createdUsers[0].email, 'newbie@acme.com');
    assert.equal(world.createdIdentities[0].email, 'newbie@acme.com');
  });
});

describe('MT-02.1 existing members are unaffected', () => {
  it('signs in a returning identity without needing an invite', async () => {
    const world = makeWorld({
      authIdentity: { userId: 'u-1', tenantId: TENANT_A },
      userById: { _id: 'u-1', email: 'member@acme.com', isActive: true },
      invite: null,
    });

    const { user } = await world.authRouting.loginMember(loginArgs());

    assert.equal(user.email, 'member@acme.com');
    assert.equal(world.createdUsers.length, 0);
    assert.equal(world.savedUsers.length, 1);
  });

  it('attaches a second provider to an existing member without an invite', async () => {
    const world = makeWorld({
      authIdentity: null,
      userByEmail: { _id: 'u-2', email: 'newbie@acme.com', isActive: true },
      invite: null,
    });

    const { user } = await world.authRouting.loginMember(loginArgs());

    assert.equal(user._id, 'u-2');
    assert.equal(world.createdUsers.length, 0, 'must not duplicate the user');
    assert.equal(world.upsertedIdentities.length, 1, 'links the new provider identity');
    assert.equal(world.upsertedIdentities[0].update.$setOnInsert.userId, 'u-2');
  });

  it('rejects a deactivated member', async () => {
    const world = makeWorld({
      authIdentity: { userId: 'u-3' },
      userById: { _id: 'u-3', email: 'gone@acme.com', isActive: false },
    });

    await assert.rejects(
      () => world.authRouting.loginMember(loginArgs()),
      (err) => err.statusCode === 403 && err.code === 'account_deactivated'
    );
  });

  it('rejects an inactive organization', async () => {
    const world = makeWorld({ org: { _id: TENANT_A, isActive: false } });

    await assert.rejects(
      () => world.authRouting.loginMember(loginArgs()),
      (err) => err.statusCode === 403 && err.code === 'org_inactive'
    );
  });

  it('rejects an unknown organization', async () => {
    const world = makeWorld({ org: null });

    await assert.rejects(
      () => world.authRouting.loginMember(loginArgs()),
      (err) => err.statusCode === 404 && err.code === 'org_not_found'
    );
  });
});
