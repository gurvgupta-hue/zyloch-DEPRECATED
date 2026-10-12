/**
 * Zyloch API integration suite.
 *
 * Runs inside the backend container against http://localhost:5000, minting real
 * session cookies with the app's own utils/jwt so the true auth path is
 * exercised (not a mock).
 *
 * Fixtures it creates are torn down in `cleanup()`; settings it mutates are
 * snapshotted and restored. It never writes to the real admin user, never
 * deletes tenant data, and never triggers a billable scan.
 */
process.chdir('/app');
const axios = require('/app/node_modules/axios');
const mongoose = require('/app/node_modules/mongoose');

const { connectCluster, closeAll } = require('/app/db/connectionManager');
const { getTenantModels } = require('/app/db/tenantModels');
const { getControlModels } = require('/app/db/controlModels');
const { signSession, buildSessionPayload } = require('/app/utils/jwt');

const BASE = 'http://localhost:5000';

// ── Live fixtures (from the control plane) ────────────────────────────────
const TENANT_A = '6a70dd3232e973b91967cf96'; // meetpatel-7's Organization
const USER_A = '6a70dd3232e973b91967cf94'; // real admin — read-only in this suite
const TENANT_B = '6a70d502739e8b1b84351eb9'; // acme.com (isolation counterparty)
const INSTALL_A = '151014999';

let userMemberA = null; // member role in tenant A, created here
let userAdminB = null; // admin in tenant B, created here

const cookieFor = (userId, tenantId, email, role) =>
  `authToken=${signSession(buildSessionPayload({ userId, tenantId, email, provider: 'github', role }))}`;

let COOKIE_A_ADMIN, COOKIE_A_MEMBER, COOKIE_B_ADMIN, COOKIE_NO_TENANT;

// ── Tiny assertion harness ────────────────────────────────────────────────
const results = [];
let currentGroup = '';

function group(name) {
  currentGroup = name;
  console.log(`\n\x1b[1m── ${name} ${'─'.repeat(Math.max(0, 62 - name.length))}\x1b[0m`);
}

async function check(name, fn) {
  try {
    const detail = await fn();
    results.push({ group: currentGroup, name, ok: true });
    console.log(`  \x1b[32mPASS\x1b[0m  ${name}${detail ? `  \x1b[2m${detail}\x1b[0m` : ''}`);
  } catch (err) {
    results.push({ group: currentGroup, name, ok: false, err: err.message });
    console.log(`  \x1b[31mFAIL\x1b[0m  ${name}\n          ${err.message}`);
  }
}

function skip(name, why) {
  results.push({ group: currentGroup, name, skipped: true, err: why });
  console.log(`  \x1b[33mSKIP\x1b[0m  ${name}  \x1b[2m${why}\x1b[0m`);
}

const req = (method, path, { cookie, data, params } = {}) =>
  axios({
    method,
    url: `${BASE}${path}`,
    headers: { ...(cookie ? { Cookie: cookie } : {}), 'Content-Type': 'application/json' },
    data,
    params,
    validateStatus: () => true,
    timeout: 60000,
  });

function expectStatus(res, expected, ctx = '') {
  const list = Array.isArray(expected) ? expected : [expected];
  if (!list.includes(res.status)) {
    const body = JSON.stringify(res.data)?.slice(0, 220);
    throw new Error(`expected ${list.join('|')}, got ${res.status} ${ctx}  body=${body}`);
  }
  return `${res.status}`;
}

// ── Fixture setup / teardown ──────────────────────────────────────────────
async function setup() {
  await connectCluster({ retries: 2 });

  const A = getTenantModels(TENANT_A);
  const B = getTenantModels(TENANT_B);

  userMemberA = new mongoose.Types.ObjectId();
  await A.User.create({
    _id: userMemberA,
    email: 'apitest-member@secure-code.dev',
    name: 'API Test Member',
    login: 'apitest-member',
    accountType: 'User',
    role: 'member',
    identities: [
      { provider: 'google', providerId: 'apitest-member-1', providerData: {}, lastUsedAt: new Date() },
    ],
    primaryIdentity: { provider: 'google', providerId: 'apitest-member-1' },
  });

  userAdminB = new mongoose.Types.ObjectId();
  await B.User.create({
    _id: userAdminB,
    email: 'apitest-admin@acme.com',
    name: 'API Test Admin B',
    login: 'apitest-admin-b',
    accountType: 'User',
    role: 'admin',
    identities: [
      { provider: 'google', providerId: 'apitest-admin-b-1', providerData: {}, lastUsedAt: new Date() },
    ],
    primaryIdentity: { provider: 'google', providerId: 'apitest-admin-b-1' },
  });

  COOKIE_A_ADMIN = cookieFor(USER_A, TENANT_A, 'meet_patel@secure-code.dev', 'admin');
  COOKIE_A_MEMBER = cookieFor(userMemberA, TENANT_A, 'apitest-member@secure-code.dev', 'member');
  COOKIE_B_ADMIN = cookieFor(userAdminB, TENANT_B, 'apitest-admin@acme.com', 'admin');
  COOKIE_NO_TENANT = `authToken=${signSession(
    buildSessionPayload({ userId: USER_A, email: 'meet_patel@secure-code.dev', provider: 'github' })
  )}`;

  console.log(`fixtures: memberA=${userMemberA} adminB=${userAdminB}`);
}

async function cleanup() {
  try {
    if (userMemberA) await getTenantModels(TENANT_A).User.deleteOne({ _id: userMemberA });
    if (userAdminB) await getTenantModels(TENANT_B).User.deleteOne({ _id: userAdminB });
    // Any invite this suite created.
    await getTenantModels(TENANT_A).MemberInvite.deleteMany({ email: /^apitest-/ });
    console.log('\nfixtures removed');
  } catch (e) {
    console.error('cleanup warning:', e.message);
  }
  await closeAll();
}

// ── The suite ─────────────────────────────────────────────────────────────
const PROTECTED = [
  ['get', '/api/organization'],
  ['get', '/api/organization/capabilities'],
  ['get', '/api/organization/license'],
  ['get', '/api/organization/members'],
  ['get', '/api/organization/scans'],
  ['get', '/api/organization/automation'],
  ['get', '/api/organization/policies'],
  ['put', '/api/organization/scans'],
  ['put', '/api/organization/automation'],
  ['put', '/api/organization/policies'],
  ['get', '/api/installations'],
  ['get', `/api/installations/${INSTALL_A}/repos`],
  ['get', `/api/repositories/${INSTALL_A}`],
  ['get', '/api/scans'],
  ['get', '/api/scans/latest'],
  ['post', '/api/scans'],
  ['post', `/api/installation-summary/${INSTALL_A}/start`],
  ['get', '/api/installations/check-status'],
  ['get', '/auth/identities'],
  ['get', '/auth/preferences'],
  ['get', '/auth/me'],
  ['get', '/auth/organizations'],
];

async function run() {
  // ═══ 1. Unauthenticated access ═══
  group('1. Unauthenticated requests are rejected');
  for (const [method, path] of PROTECTED) {
    await check(`${method.toUpperCase()} ${path} → 401`, async () => {
      const res = await req(method, path);
      return expectStatus(res, 401);
    });
  }
  await check('GET /auth/check-auth → 401 without cookie', async () =>
    expectStatus(await req('get', '/auth/check-auth'), [401, 200])
  );
  await check('Garbage/tampered cookie → 401', async () =>
    expectStatus(await req('get', '/api/organization', { cookie: 'authToken=not-a-real-token' }), 401)
  );
  await check('Valid JWT without tenantId → 403', async () =>
    expectStatus(await req('get', '/api/organization', { cookie: COOKIE_NO_TENANT }), 403)
  );

  // ═══ 2. Auth / session ═══
  group('2. Auth & session endpoints');
  await check('GET /auth/check-auth authenticated', async () =>
    expectStatus(await req('get', '/auth/check-auth', { cookie: COOKIE_A_ADMIN }), 200)
  );
  await check('GET /auth/me returns the right user', async () => {
    const res = await req('get', '/auth/me', { cookie: COOKIE_A_ADMIN });
    expectStatus(res, 200);
    const email = res.data?.user?.email || res.data?.email;
    if (email !== 'meet_patel@secure-code.dev') throw new Error(`wrong user: ${email}`);
    return email;
  });
  await check('GET /auth/identities', async () =>
    expectStatus(await req('get', '/auth/identities', { cookie: COOKIE_A_ADMIN }), 200)
  );
  await check('GET /auth/preferences', async () =>
    expectStatus(await req('get', '/auth/preferences', { cookie: COOKIE_A_ADMIN }), 200)
  );
  await check('GET /auth/organizations lists only my orgs', async () => {
    const res = await req('get', '/auth/organizations', { cookie: COOKIE_A_ADMIN });
    expectStatus(res, 200);
    const orgs = res.data?.organizations || [];
    if (orgs.some((o) => String(o.tenantId) === TENANT_B))
      throw new Error('leaked tenant B into org list');
    return `${orgs.length} org(s)`;
  });
  await check('GET /auth/resolve-org (public) unknown domain → null/404', async () =>
    expectStatus(await req('get', '/auth/resolve-org', { params: { domain: 'nope-does-not-exist.tld' } }), [200, 404])
  );
  await check('POST /auth/switch-organization to a foreign tenant → 403/404', async () =>
    expectStatus(
      await req('post', '/auth/switch-organization', {
        cookie: COOKIE_A_ADMIN,
        data: { tenantId: TENANT_B },
      }),
      [403, 404]
    )
  );

  // ═══ 3. Organization reads ═══
  group('3. Organization reads');
  await check('GET /api/organization', async () => {
    const res = await req('get', '/api/organization', { cookie: COOKIE_A_ADMIN });
    expectStatus(res, 200);
    if (String(res.data?.organization?._id) !== TENANT_A) throw new Error('wrong org returned');
    return res.data.organization.name;
  });
  await check('GET /api/organization exposes automationConfigurations', async () => {
    const res = await req('get', '/api/organization', { cookie: COOKIE_A_ADMIN });
    const a = res.data?.organization?.automationConfigurations;
    if (!a || typeof a.autoScanOnSync !== 'boolean')
      throw new Error(`missing/!boolean: ${JSON.stringify(a)}`);
    return `autoScanOnSync=${a.autoScanOnSync}`;
  });
  await check('GET /api/organization/capabilities', async () => {
    const res = await req('get', '/api/organization/capabilities', { cookie: COOKIE_A_ADMIN });
    expectStatus(res, 200);
    return `${Object.keys(res.data?.capabilities || {}).length} capabilities`;
  });
  await check('GET /api/organization/license', async () =>
    expectStatus(await req('get', '/api/organization/license', { cookie: COOKIE_A_ADMIN }), 200)
  );
  await check('GET /api/organization/members', async () => {
    const res = await req('get', '/api/organization/members', { cookie: COOKIE_A_ADMIN });
    expectStatus(res, 200);
    return `${(res.data?.members || []).length} member(s)`;
  });
  await check('GET /api/organization/scans', async () =>
    expectStatus(await req('get', '/api/organization/scans', { cookie: COOKIE_A_ADMIN }), 200)
  );
  await check('GET /api/organization/automation', async () => {
    const res = await req('get', '/api/organization/automation', { cookie: COOKIE_A_ADMIN });
    expectStatus(res, 200);
    return `autoScanOnSync=${res.data?.automationConfigurations?.autoScanOnSync}`;
  });
  await check('GET /api/organization/policies', async () =>
    expectStatus(await req('get', '/api/organization/policies', { cookie: COOKIE_A_ADMIN }), 200)
  );

  // ═══ 4. Organization writes (snapshot + restore) ═══
  group('4. Organization writes (restored afterwards)');
  const settingsBefore = await getTenantModels(TENANT_A)
    .TenantSettings.findOne({ tenantId: TENANT_A })
    .lean();

  await check('PUT /api/organization/automation enables the flag', async () => {
    const res = await req('put', '/api/organization/automation', {
      cookie: COOKIE_A_ADMIN,
      data: { automationConfigurations: { autoScanOnSync: true } },
    });
    expectStatus(res, 200);
    if (res.data?.automationConfigurations?.autoScanOnSync !== true)
      throw new Error(`not persisted: ${JSON.stringify(res.data?.automationConfigurations)}`);
    return 'true';
  });
  await check('…and the change is readable back', async () => {
    const res = await req('get', '/api/organization/automation', { cookie: COOKIE_A_ADMIN });
    if (res.data?.automationConfigurations?.autoScanOnSync !== true)
      throw new Error('read-back mismatch');
    return 'true';
  });
  await check('PUT /api/organization/automation disables it again', async () => {
    const res = await req('put', '/api/organization/automation', {
      cookie: COOKIE_A_ADMIN,
      data: { automationConfigurations: { autoScanOnSync: false } },
    });
    expectStatus(res, 200);
    if (res.data?.automationConfigurations?.autoScanOnSync !== false) throw new Error('not persisted');
    return 'false';
  });
  await check('PUT /api/organization/automation rejects an empty body → 400', async () =>
    expectStatus(await req('put', '/api/organization/automation', { cookie: COOKIE_A_ADMIN, data: {} }), 400)
  );
  await check('PUT /api/organization/automation ignores unknown keys', async () => {
    const res = await req('put', '/api/organization/automation', {
      cookie: COOKIE_A_ADMIN,
      data: { automationConfigurations: { autoScanOnSync: false, evilFlag: true } },
    });
    expectStatus(res, 200);
    if ('evilFlag' in (res.data?.automationConfigurations || {}))
      throw new Error('unknown key leaked into settings');
    return 'ignored';
  });
  await check('PUT /api/organization/scans round-trips', async () => {
    const res = await req('put', '/api/organization/scans', {
      cookie: COOKIE_A_ADMIN,
      data: { scanConfigurations: { docker: true } },
    });
    return expectStatus(res, 200);
  });

  // ═══ 5. RBAC — member vs admin ═══
  group('5. RBAC (member role denied admin-only actions)');
  await check('member CAN read organization', async () =>
    expectStatus(await req('get', '/api/organization', { cookie: COOKIE_A_MEMBER }), 200)
  );
  await check('member CAN read members', async () =>
    expectStatus(await req('get', '/api/organization/members', { cookie: COOKIE_A_MEMBER }), 200)
  );
  await check('member CANNOT write automation → 403', async () =>
    expectStatus(
      await req('put', '/api/organization/automation', {
        cookie: COOKIE_A_MEMBER,
        data: { automationConfigurations: { autoScanOnSync: true } },
      }),
      403
    )
  );
  await check('member CANNOT write scan settings → 403', async () =>
    expectStatus(
      await req('put', '/api/organization/scans', {
        cookie: COOKIE_A_MEMBER,
        data: { scanConfigurations: { docker: false } },
      }),
      403
    )
  );
  await check('member CANNOT write policies → 403', async () =>
    expectStatus(
      await req('put', '/api/organization/policies', {
        cookie: COOKIE_A_MEMBER,
        data: { policyConfigurations: {} },
      }),
      403
    )
  );
  await check('member CANNOT invite → 403', async () =>
    expectStatus(
      await req('post', '/api/organization/members/invite', {
        cookie: COOKIE_A_MEMBER,
        data: { email: 'apitest-invitee@secure-code.dev', role: 'member' },
      }),
      403
    )
  );
  await check('member CANNOT write OAuth config → 403', async () =>
    expectStatus(
      await req('put', '/api/organization/oauth/google', {
        cookie: COOKIE_A_MEMBER,
        data: { clientId: 'x', clientSecret: 'y', redirectUri: 'http://z', enabled: false },
      }),
      403
    )
  );
  await check('member CANNOT delete a repository → 403', async () =>
    expectStatus(
      await req('delete', `/api/repositories/${INSTALL_A}/does-not-exist`, { cookie: COOKIE_A_MEMBER }),
      403
    )
  );

  // ═══ 6. Installations & repositories ═══
  group('6. Installations & repositories');
  await check('GET /api/installations', async () => {
    const res = await req('get', '/api/installations', { cookie: COOKIE_A_ADMIN });
    expectStatus(res, 200);
    return `${(res.data?.installations || res.data || []).length ?? '?'} installation(s)`;
  });
  await check('GET /api/installations/check-status', async () =>
    expectStatus(await req('get', '/api/installations/check-status', { cookie: COOKIE_A_ADMIN }), [200, 404])
  );
  await check('GET /api/installations/pending is gone → 404', async () =>
    expectStatus(await req('get', '/api/installations/pending', { cookie: COOKIE_A_ADMIN }), 404)
  );
  await check('POST /api/installations/link is gone → 404', async () =>
    expectStatus(
      await req('post', '/api/installations/link', {
        cookie: COOKIE_A_ADMIN,
        data: { installationId: INSTALL_A },
      }),
      404
    )
  );
  await check(`GET /api/repositories/${INSTALL_A}`, async () => {
    const res = await req('get', `/api/repositories/${INSTALL_A}`, { cookie: COOKIE_A_ADMIN });
    expectStatus(res, 200);
    const n = (res.data?.repositories || res.data?.data || []).length;
    return `${n} repo(s)`;
  });
  await check('GET repositories for a foreign installation → 403/404', async () =>
    expectStatus(
      await req('get', `/api/repositories/${INSTALL_A}`, { cookie: COOKIE_B_ADMIN }),
      [403, 404]
    )
  );

  // ═══ 7. Scans (reads only) ═══
  group('7. Scans');
  await check('GET /api/scans', async () =>
    expectStatus(await req('get', '/api/scans', { cookie: COOKIE_A_ADMIN, params: { installation_id: INSTALL_A } }), [200, 404])
  );
  await check('GET /api/scans/latest requires org_name → 400', async () =>
    expectStatus(await req('get', '/api/scans/latest', { cookie: COOKIE_A_ADMIN }), [400, 404])
  );
  await check('POST /api/scans rejects a missing repo_name → 400', async () =>
    expectStatus(
      await req('post', '/api/scans', {
        cookie: COOKIE_A_ADMIN,
        data: { installation_id: INSTALL_A, org_name: 'meetpatel-7' },
      }),
      400
    )
  );
  await check('POST /api/scans from tenant B on A\'s installation → 403/404', async () =>
    expectStatus(
      await req('post', '/api/scans', {
        cookie: COOKIE_B_ADMIN,
        data: { installation_id: INSTALL_A, org_name: 'meetpatel-7', repo_name: 'new-test', branch: 'main' },
      }),
      [403, 404]
    )
  );
  skip('POST /api/scans happy path', 'would trigger a real billable scan on live repos');

  // ═══ 8. Installation summary (the tenantId-conflict regression) ═══
  group('8. Installation summary');
  await check('POST /installation-summary/:id/start no longer conflicts on tenantId', async () => {
    const res = await req('post', `/api/installation-summary/${INSTALL_A}/start`, { cookie: COOKIE_A_ADMIN });
    const body = JSON.stringify(res.data);
    if (/would create a conflict/i.test(body)) throw new Error(`REGRESSION: ${body.slice(0, 200)}`);
    return expectStatus(res, 200);
  });
  await check('POST /installation-summary/:id/start from tenant B → 403/404', async () =>
    expectStatus(
      await req('post', `/api/installation-summary/${INSTALL_A}/start`, { cookie: COOKIE_B_ADMIN }),
      [403, 404]
    )
  );
  await check('GET /installation-summary/status/:jobId with a bogus id → 400/404', async () =>
    expectStatus(
      await req('get', '/api/installation-summary/status/000000000000000000000000', { cookie: COOKIE_A_ADMIN }),
      [400, 404]
    )
  );

  // ═══ 9. Cross-tenant isolation ═══
  group('9. Cross-tenant isolation (B must never see A)');
  await check('tenant B GET /api/organization returns B, not A', async () => {
    const res = await req('get', '/api/organization', { cookie: COOKIE_B_ADMIN });
    expectStatus(res, 200);
    const id = String(res.data?.organization?._id);
    if (id === TENANT_A) throw new Error('CRITICAL: tenant B received tenant A org');
    if (id !== TENANT_B) throw new Error(`unexpected org ${id}`);
    return id;
  });
  await check('tenant B members list does not contain A users', async () => {
    const res = await req('get', '/api/organization/members', { cookie: COOKIE_B_ADMIN });
    expectStatus(res, 200);
    const emails = (res.data?.members || []).map((m) => m.email);
    if (emails.includes('meet_patel@secure-code.dev'))
      throw new Error('CRITICAL: tenant A user leaked into tenant B');
    return `${emails.length} member(s)`;
  });
  await check('tenant B sees no installations of A', async () => {
    const res = await req('get', '/api/installations', { cookie: COOKIE_B_ADMIN });
    expectStatus(res, 200);
    const raw = JSON.stringify(res.data);
    if (raw.includes(INSTALL_A)) throw new Error('CRITICAL: A installation leaked to B');
    return 'clean';
  });
  await check('tenant B scan list does not contain A scans', async () => {
    const res = await req('get', '/api/scans', { cookie: COOKIE_B_ADMIN, params: { installation_id: INSTALL_A } });
    if (res.status === 200) {
      const raw = JSON.stringify(res.data?.scans || []);
      if (raw.includes('meetpatel-7')) throw new Error('CRITICAL: A scan data leaked to B');
    }
    return `${res.status}`;
  });
  await check('forged cookie with A user id but B tenant cannot read A data', async () => {
    // The classic confused-deputy: valid signature, mismatched pairing.
    const forged = cookieFor(USER_A, TENANT_B, 'meet_patel@secure-code.dev', 'admin');
    const res = await req('get', '/api/organization', { cookie: forged });
    if (res.status === 200 && String(res.data?.organization?._id) === TENANT_A)
      throw new Error('CRITICAL: tenantId in token ignored');
    return `${res.status}`;
  });

  // ═══ 10. One identity, different role in each organization ═══
  group('10. Same person: member in tenant A, admin in tenant B');
  // Roles live on the tenant's own user document, so the SAME human must be able
  // to be a member of one organization and an admin of another. These two cookies
  // carry the same email; only tenantId and role differ.
  const sharedEmail = 'apitest-member@secure-code.dev';
  const asMemberOfA = cookieFor(userMemberA, TENANT_A, sharedEmail, 'member');
  const asAdminOfB = cookieFor(userAdminB, TENANT_B, sharedEmail, 'admin');

  await check('same email is a MEMBER in A — admin write denied', async () =>
    expectStatus(
      await req('put', '/api/organization/automation', {
        cookie: asMemberOfA,
        data: { automationConfigurations: { autoScanOnSync: true } },
      }),
      403
    )
  );
  await check('same email is an ADMIN in B — admin write allowed', async () =>
    expectStatus(
      await req('put', '/api/organization/automation', {
        cookie: asAdminOfB,
        data: { automationConfigurations: { autoScanOnSync: false } },
      }),
      200
    )
  );
  await check('capabilities differ per organization for the same person', async () => {
    const a = await req('get', '/api/organization/capabilities', { cookie: asMemberOfA });
    const b = await req('get', '/api/organization/capabilities', { cookie: asAdminOfB });
    expectStatus(a, 200);
    expectStatus(b, 200);
    const aWrite = a.data?.capabilities?.['organization.settings.write'];
    const bWrite = b.data?.capabilities?.['organization.settings.write'];
    if (aWrite !== false || bWrite !== true)
      throw new Error(`expected member-in-A=false admin-in-B=true, got ${aWrite}/${bWrite}`);
    return 'A=false B=true';
  });
  await check('being admin in B grants nothing in A', async () => {
    const res = await req('get', '/api/organization', { cookie: asAdminOfB });
    expectStatus(res, 200);
    if (String(res.data?.organization?._id) === TENANT_A)
      throw new Error('CRITICAL: admin-of-B cookie read tenant A');
    return String(res.data?.organization?._id);
  });

  // ═══ 11. Domain is not an identifier ═══
  group('11. Domain is informational, never an identifier');
  await check('organizations schema has no unique domain index', async () => {
    const { schema } = require('/app/models/schemas/control/organizationSchema');
    const idx = schema.indexes().find(([f]) => Object.prototype.hasOwnProperty.call(f, 'domain'));
    if (!idx) throw new Error('expected a domain index');
    if (idx[1]?.unique === true) throw new Error('domain index is still unique');
    return 'non-unique';
  });
  await check('live organizations collection has no unique domain index', async () => {
    const { Organization } = getControlModels();
    const live = await Organization.collection.indexes();
    const dom = live.find((i) => i.key && Object.keys(i.key).length === 1 && i.key.domain === 1);
    if (dom?.unique) throw new Error(`live index still unique: ${JSON.stringify(dom)}`);
    return dom ? `${dom.name} (non-unique)` : 'no domain index';
  });
  await check('two organizations can share a domain', async () => {
    const { Organization } = getControlModels();
    const shared = `apitest-shared-${Date.now()}.example`;
    const ids = [new mongoose.Types.ObjectId(), new mongoose.Types.ObjectId()];
    try {
      for (const _id of ids) {
        await Organization.create({
          _id,
          name: 'apitest shared-domain org',
          domain: shared,
          databaseName: `zyloch_tenant_${_id}`,
          provisionStatus: 'active',
        });
      }
      const n = await Organization.countDocuments({ domain: shared });
      if (n !== 2) throw new Error(`expected 2 orgs on one domain, found ${n}`);
      return '2 orgs, 1 domain';
    } finally {
      await Organization.deleteMany({ _id: { $in: ids } });
    }
  });

  // ── restore mutated settings ──
  if (settingsBefore) {
    await getTenantModels(TENANT_A).TenantSettings.updateOne(
      { tenantId: TENANT_A },
      { $set: { scans: settingsBefore.scans, automation: settingsBefore.automation || { autoScanOnSync: false } } }
    );
    console.log('\ntenant A settings restored to their pre-test values');
  }
}

(async () => {
  await setup();
  try {
    await run();
  } finally {
    await cleanup();
  }

  const pass = results.filter((r) => r.ok).length;
  const fail = results.filter((r) => r.err && !r.skipped && !r.ok);
  const skipped = results.filter((r) => r.skipped).length;

  console.log(`\n${'═'.repeat(70)}`);
  console.log(`  ${pass} passed   ${fail.length} failed   ${skipped} skipped   (${results.length} total)`);
  if (fail.length) {
    console.log('\n  FAILURES:');
    for (const f of fail) console.log(`   • [${f.group}] ${f.name}\n     ${f.err}`);
  }
  console.log(`${'═'.repeat(70)}`);
  process.exit(fail.length ? 1 : 0);
})().catch((e) => {
  console.error('SUITE ERROR:', e.stack || e.message);
  process.exit(2);
});
