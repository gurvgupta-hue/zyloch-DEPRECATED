#!/usr/bin/env node
/**
 * Cross-tenant isolation probe.
 *
 * Drives a running Zyloch API with two seeded tenants and asserts the three
 * properties multi-tenancy depends on:
 *
 *   1. OWN     — tenant A's session reaches tenant A's resources.
 *   2. CROSS   — tenant A's session is REFUSED tenant B's resource ids.
 *   3. ANON    — no session reaches anything.
 *
 * Plus role separation (member cannot perform admin-only actions) and the
 * public-endpoint contract.
 *
 * Usage:
 *   node scripts/mt-test/seed-tenants.js --tenants 2 --out /tmp/mt-fixtures.json
 *   node scripts/mt-test/isolation-probe.js --fixtures /tmp/mt-fixtures.json
 *
 * Exit code is non-zero if any isolation assertion fails, so it can gate CI.
 */

const fs = require('fs');

function arg(name, fallback = null) {
  const i = process.argv.indexOf(`--${name}`);
  return i !== -1 && process.argv[i + 1] ? process.argv[i + 1] : fallback;
}

const fixturesPath = arg('fixtures', '/tmp/mt-fixtures.json');

let fixtures;
try {
  fixtures = JSON.parse(fs.readFileSync(fixturesPath, 'utf8'));
} catch (err) {
  console.error(`\nCould not read fixtures at ${fixturesPath}\n  ${err.message}\n`);
  console.error('Seed them first:');
  console.error(`  node scripts/mt-test/seed-tenants.js --tenants 2 --out ${fixturesPath}\n`);
  process.exit(1);
}

const BASE = arg('api', fixtures.apiBaseUrl || 'http://localhost:5000');
const VERBOSE = process.argv.includes('--verbose');

const [A, B] = fixtures.tenants || [];
if (!A || !B) {
  console.error('\nNeed at least 2 seeded tenants for cross-tenant probing.');
  console.error('  node scripts/mt-test/seed-tenants.js --tenants 2\n');
  process.exit(1);
}

const results = [];
let failures = 0;

async function call(pathname, { cookie, method = 'GET', body } = {}) {
  const res = await fetch(`${BASE}${pathname}`, {
    method,
    headers: {
      ...(cookie ? { cookie } : {}),
      ...(body ? { 'content-type': 'application/json' } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
    redirect: 'manual',
  });
  let payload = null;
  try {
    payload = await res.json();
  } catch {
    /* non-JSON (redirect/HTML) is fine */
  }
  return { status: res.status, payload };
}

/**
 * @param {string} name
 * @param {number[]} expected acceptable status codes
 */
async function probe(name, category, pathname, options, expected) {
  let outcome;
  try {
    const { status, payload } = await call(pathname, options);
    const ok = expected.includes(status);
    if (!ok) failures += 1;
    outcome = {
      name,
      category,
      pathname,
      status,
      expected: expected.join('/'),
      ok,
      detail: payload?.message || '',
    };
  } catch (err) {
    failures += 1;
    outcome = { name, category, pathname, status: 'ERR', expected: expected.join('/'), ok: false, detail: err.message };
  }
  results.push(outcome);
  if (VERBOSE || !outcome.ok) {
    console.log(
      `${outcome.ok ? '  ok  ' : '  FAIL'} [${category}] ${name} → ${outcome.status} (want ${outcome.expected}) ${outcome.detail}`
    );
  }
  return outcome;
}

/** Endpoints that take a tenant-owned resource id in the path or query. */
function resourceRoutes(tenant) {
  return [
    { name: 'list repositories', path: `/api/repositories/${tenant.installationId}` },
    {
      name: 'repository branches',
      path: `/api/repositories/${tenant.installationId}/${tenant.repositoryName}/branches`,
    },
    { name: 'list scans', path: `/api/scans?installationId=${tenant.installationId}` },
    {
      name: 'latest scan',
      path: `/api/scans/latest?installationId=${tenant.installationId}&org_name=${tenant.accountLogin}&repo_name=${tenant.repositoryName}`,
    },
    { name: 'installation repos', path: `/api/installations/${tenant.installationId}/repos` },
    {
      name: 'installation branches',
      path: `/api/installations/${tenant.installationId}/repos/${tenant.accountLogin}/${tenant.repositoryName}/branches`,
    },
  ];
}

/** Tenant-scoped endpoints with no resource id — scope comes from the session. */
const SESSION_SCOPED = [
  { name: 'current user', path: '/auth/me' },
  { name: 'organization', path: '/api/organization' },
  { name: 'capabilities', path: '/api/organization/capabilities' },
  { name: 'license', path: '/api/organization/license' },
  { name: 'members', path: '/api/organization/members' },
  { name: 'scan config', path: '/api/organization/scans' },
  { name: 'policies', path: '/api/organization/policies' },
  { name: 'installations', path: '/api/installations' },
  { name: 'pending links', path: '/api/installations/pending' },
];

/** Fail fast and clearly rather than reporting 50 "fetch failed" assertions. */
async function preflight() {
  try {
    await fetch(`${BASE}/auth/check-auth`, { redirect: 'manual' });
  } catch (err) {
    console.error(`\nCannot reach the API at ${BASE}`);
    console.error('  Start it first:  cd Zyloch-Backend && npm run dev');
    console.error('  Or point elsewhere:  --api http://host:port\n');
    process.exit(1);
  }
}

async function run() {
  await preflight();

  console.log(`\nCross-tenant isolation probe`);
  console.log(`API      : ${BASE}`);
  console.log(`Tenant A : ${A.slug} (${A.tenantId}) install=${A.installationId}`);
  console.log(`Tenant B : ${B.slug} (${B.tenantId}) install=${B.installationId}\n`);

  // ---- 1. OWN: a tenant reaches its own resources -------------------------
  for (const route of SESSION_SCOPED) {
    await probe(route.name, 'OWN', route.path, { cookie: A.admin.header }, [200]);
  }
  for (const route of resourceRoutes(A)) {
    // 5xx from an unreachable GitHub/GHAPP is not an isolation failure; the
    // point here is that the tenant check did not reject the request.
    await probe(route.name, 'OWN', route.path, { cookie: A.admin.header }, [200, 500, 502]);
  }

  // ---- 2. CROSS: tenant A must not touch tenant B's resources -------------
  for (const route of resourceRoutes(B)) {
    await probe(
      `A → B: ${route.name}`,
      'CROSS',
      route.path,
      { cookie: A.admin.header },
      [403, 404]
    );
  }

  // Claiming tenant B's installation must be refused even for an admin.
  await probe(
    'A claims B installation',
    'CROSS',
    '/api/installations/link',
    { cookie: A.admin.header, method: 'POST', body: { installationId: B.installationId } },
    [403, 409]
  );

  // Deleting tenant B's repository data.
  await probe(
    'A deletes B repository',
    'CROSS',
    `/api/repositories/${B.installationId}/${B.repositoryName}`,
    { cookie: A.admin.header, method: 'DELETE' },
    [403, 404]
  );

  // Triggering a scan against tenant B's installation.
  await probe(
    'A scans B installation',
    'CROSS',
    '/api/scans',
    {
      cookie: A.admin.header,
      method: 'POST',
      body: {
        installation_id: B.installationId,
        org_name: B.accountLogin,
        repo_name: B.repositoryName,
      },
    },
    [403, 404]
  );

  // Switching into tenant B without an identity there.
  await probe(
    'A switches to B org',
    'CROSS',
    '/auth/switch-organization',
    { cookie: A.admin.header, method: 'POST', body: { tenantId: B.tenantId } },
    [403, 404]
  );

  // ---- 3. ANON: no session reaches nothing --------------------------------
  for (const route of [...SESSION_SCOPED, ...resourceRoutes(A)]) {
    await probe(`anon: ${route.name}`, 'ANON', route.path, {}, [401]);
  }

  // ---- 4. ROLE: member must not perform admin-only actions ----------------
  const adminOnly = [
    { name: 'invite member', path: '/api/organization/members/invite', method: 'POST', body: { email: 'x@y.com' } },
    { name: 'update scan config', path: '/api/organization/scans', method: 'PUT', body: { scanConfigurations: {} } },
    { name: 'update policies', path: '/api/organization/policies', method: 'PUT', body: { scanners: {} } },
    { name: 'set google oauth', path: '/api/organization/oauth/google', method: 'PUT', body: {} },
    { name: 'link installation', path: '/api/installations/link', method: 'POST', body: { installationId: A.installationId } },
    { name: 'pending links', path: '/api/installations/pending', method: 'GET' },
    { name: 'delete repository', path: `/api/repositories/${A.installationId}/${A.repositoryName}`, method: 'DELETE' },
  ];
  for (const route of adminOnly) {
    await probe(
      `member: ${route.name}`,
      'ROLE',
      route.path,
      { cookie: A.member.header, method: route.method, body: route.body },
      [403]
    );
  }
  // ...but a member can still read.
  await probe('member reads organization', 'ROLE', '/api/organization', { cookie: A.member.header }, [200]);
  await probe('member reads members', 'ROLE', '/api/organization/members', { cookie: A.member.header }, [200]);

  // ---- 5. PUBLIC: pre-login endpoints disclose the minimum ---------------
  const resolved = await probe(
    'resolve-org by domain',
    'PUBLIC',
    `/auth/resolve-org?domain=${A.domain}`,
    {},
    [200, 404, 429]
  );
  if (resolved.status === 200) {
    const org = (await call(`/auth/resolve-org?domain=${A.domain}`)).payload?.organization || {};
    const leaked = ['name', 'domain'].filter((k) => k in org);
    if (leaked.length) {
      failures += 1;
      console.log(`  FAIL [PUBLIC] resolve-org leaks ${leaked.join(', ')} (should return tenantId only)`);
      results.push({ name: 'resolve-org minimal disclosure', category: 'PUBLIC', ok: false, status: 200, expected: 'tenantId only', detail: `leaked ${leaked.join(', ')}` });
    } else {
      results.push({ name: 'resolve-org minimal disclosure', category: 'PUBLIC', ok: true, status: 200, expected: 'tenantId only', detail: '' });
    }
  }
  await probe(
    'resolve-org by orgId is not a lookup',
    'PUBLIC',
    `/auth/resolve-org?orgId=${A.tenantId}`,
    {},
    [404, 429]
  );
  await probe('providers', 'PUBLIC', `/api/organization/${A.tenantId}/providers`, {}, [200, 404, 429]);

  // ---- 6. TAMPER: a forged/garbage session must not authenticate ---------
  await probe('garbage cookie', 'TAMPER', '/api/organization', { cookie: 'authToken=not-a-token' }, [401]);
  await probe(
    'truncated cookie',
    'TAMPER',
    '/api/organization',
    { cookie: `authToken=${A.admin.token.slice(0, -6)}` },
    [401]
  );
  await probe('empty cookie', 'TAMPER', '/api/organization', { cookie: 'authToken=' }, [401]);

  report();
}

function report() {
  const byCategory = {};
  for (const r of results) {
    byCategory[r.category] ||= { pass: 0, fail: 0 };
    byCategory[r.category][r.ok ? 'pass' : 'fail'] += 1;
  }

  console.log('\n───────────────────────────────────────────────');
  console.log(' Category   Pass  Fail   Meaning');
  console.log('───────────────────────────────────────────────');
  const meaning = {
    OWN: 'tenant reaches its own data',
    CROSS: 'tenant blocked from other tenant data',
    ANON: 'no session reaches nothing',
    ROLE: 'member blocked from admin actions',
    PUBLIC: 'pre-login endpoints minimal',
    TAMPER: 'forged sessions rejected',
  };
  for (const [cat, counts] of Object.entries(byCategory)) {
    console.log(
      ` ${cat.padEnd(10)} ${String(counts.pass).padEnd(5)} ${String(counts.fail).padEnd(5)}  ${meaning[cat] || ''}`
    );
  }
  console.log('───────────────────────────────────────────────');

  if (failures > 0) {
    console.log(`\n✗ ${failures} isolation assertion(s) FAILED\n`);
    for (const r of results.filter((x) => !x.ok)) {
      console.log(`   [${r.category}] ${r.name}  → ${r.status} (want ${r.expected}) ${r.detail}`);
    }
    process.exit(1);
  }
  console.log(`\n✓ all ${results.length} isolation assertions passed\n`);
}

run().catch((err) => {
  if (/fetch failed|ECONNREFUSED/i.test(err.message)) {
    console.error(`\nCannot reach the API at ${BASE}`);
    console.error('  Start it first:  cd Zyloch-Backend && npm run dev');
    console.error('  Or point elsewhere:  --api http://host:port\n');
  } else {
    console.error('probe failed to run:', err.message);
  }
  process.exit(1);
});
