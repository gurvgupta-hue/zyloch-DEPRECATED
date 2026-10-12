#!/usr/bin/env node
/**
 * Seed isolated tenants for multi-tenancy testing.
 *
 * Provisions N tenants straight through the product's own services, creates an
 * admin and a member in each, and mints valid session cookies. That means the
 * whole cross-tenant test suite runs without needing GitHub OAuth in the loop,
 * while still exercising the real provisioning path (control-plane rows, tenant
 * DB, indexes, license, metrics).
 *
 * Usage (from Zyloch-Backend, so it picks up that .env):
 *   node ../scripts/mt-test/seed-tenants.js --tenants 3 --out /tmp/mt-fixtures.json
 *   node ../scripts/mt-test/seed-tenants.js --cleanup /tmp/mt-fixtures.json
 *
 * The seeded tenants are named `mt-test-<n>` and every artefact is recorded in
 * the fixtures file so `--cleanup` can remove them all again.
 */

const path = require('path');
const fs = require('fs');

const BACKEND = path.resolve(__dirname, '../../Zyloch-Backend');
require(path.join(BACKEND, 'node_modules/dotenv')).config({
  path: path.join(BACKEND, '.env'),
});

const mongoose = require(path.join(BACKEND, 'node_modules/mongoose'));
const connectDB = require(path.join(BACKEND, 'config/db'));
const { closeAll, getControlDb } = require(path.join(BACKEND, 'db/connectionManager'));
const { getControlModels } = require(path.join(BACKEND, 'db/controlModels'));
const { getTenantModels } = require(path.join(BACKEND, 'db/tenantModels'));
const { provisionTenant, offboardTenant } = require(path.join(BACKEND, 'services/tenantProvisioning'));
const { signSession, buildSessionPayload } = require(path.join(BACKEND, 'utils/jwt'));

const TEST_PREFIX = 'mt-test';

function arg(name, fallback = null) {
  const i = process.argv.indexOf(`--${name}`);
  return i !== -1 && process.argv[i + 1] ? process.argv[i + 1] : fallback;
}

/** A session cookie the API will accept, without going through OAuth. */
function mintCookie({ userId, tenantId, email, role }) {
  const token = signSession(
    buildSessionPayload({ userId, tenantId, email, provider: 'github', role })
  );
  return { token, header: `authToken=${token}` };
}

async function seedOneTenant(index) {
  const slug = `${TEST_PREFIX}-${index}`;
  const adminId = new mongoose.Types.ObjectId();
  const memberId = new mongoose.Types.ObjectId();

  const { tenantId, databaseName } = await provisionTenant({
    name: `MT Test Org ${index}`,
    domain: `${slug}.example.com`,
    adminUserId: adminId,
  });

  const { User, Installation, RepositoryData, MemberInvite } = getTenantModels(tenantId);
  const { AuthIdentity, InstallationIndex } = getControlModels();

  const adminEmail = `admin@${slug}.example.com`;
  const memberEmail = `member@${slug}.example.com`;

  await User.create({
    _id: adminId,
    email: adminEmail,
    name: `Admin ${index}`,
    login: `${slug}-admin`,
    githubId: 900000 + index,
    accountType: 'User',
    role: 'admin',
    identities: [
      {
        provider: 'github',
        providerId: String(900000 + index),
        providerData: { login: `${slug}-admin`, email: adminEmail },
        lastUsedAt: new Date(),
      },
    ],
    primaryIdentity: { provider: 'github', providerId: String(900000 + index) },
  });

  await User.create({
    _id: memberId,
    email: memberEmail,
    name: `Member ${index}`,
    login: `${slug}-member`,
    accountType: 'User',
    role: 'member',
    identities: [
      {
        provider: 'google',
        providerId: `g-${slug}`,
        providerData: { login: `${slug}-member`, email: memberEmail },
        lastUsedAt: new Date(),
      },
    ],
    primaryIdentity: { provider: 'google', providerId: `g-${slug}` },
  });

  await AuthIdentity.create([
    {
      provider: 'github',
      providerId: String(900000 + index),
      tenantId,
      userId: adminId,
      email: adminEmail,
    },
    {
      provider: 'google',
      providerId: `g-${slug}`,
      tenantId,
      userId: memberId,
      email: memberEmail,
    },
  ]);

  // A pending invite, so invite-redemption tests have something to redeem.
  await MemberInvite.create({
    tenantId,
    email: `invited@${slug}.example.com`,
    invitedBy: adminId,
    status: 'pending',
    token: `tok-${slug}-${Date.now()}`,
    expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
  });

  // An installation owned by this tenant — the key cross-tenant IDOR target.
  const installationId = 5000000 + index;
  await Installation.create({
    installationId,
    account: { id: 700000 + index, login: `${slug}-gh-org`, type: 'Organization' },
    repos: [`${slug}-gh-org/api`],
    lastFetchedAt: new Date(),
  });
  await InstallationIndex.create({
    githubInstallationId: installationId,
    tenantId,
    accountLogin: `${slug}-gh-org`,
    accountType: 'Organization',
    linkedAt: new Date(),
  });

  await RepositoryData.create({
    tenantId,
    installationId,
    accountId: 700000 + index,
    owner: `${slug}-gh-org`,
    repositoryName: 'api',
    repositoryUrl: `https://github.com/${slug}-gh-org/api`,
    isPrivate: true,
    lastActive: new Date(),
  });

  return {
    slug,
    tenantId: String(tenantId),
    databaseName,
    domain: `${slug}.example.com`,
    installationId,
    repositoryName: 'api',
    accountLogin: `${slug}-gh-org`,
    admin: {
      userId: String(adminId),
      email: adminEmail,
      role: 'admin',
      ...mintCookie({ userId: adminId, tenantId, email: adminEmail, role: 'admin' }),
    },
    member: {
      userId: String(memberId),
      email: memberEmail,
      role: 'member',
      ...mintCookie({ userId: memberId, tenantId, email: memberEmail, role: 'member' }),
    },
  };
}

async function seed() {
  const count = Number(arg('tenants', 2));
  const out = arg('out', '/tmp/mt-fixtures.json');

  await connectDB();
  console.log(`[seed] Provisioning ${count} test tenants...`);

  const tenants = [];
  for (let i = 1; i <= count; i += 1) {
    const tenant = await seedOneTenant(i);
    tenants.push(tenant);
    console.log(`  ✓ ${tenant.slug}  tenantId=${tenant.tenantId}  db=${tenant.databaseName}`);
  }

  const fixtures = {
    createdAt: new Date().toISOString(),
    apiBaseUrl: process.env.MT_TEST_API_URL || 'http://localhost:5000',
    tenants,
  };
  fs.writeFileSync(out, JSON.stringify(fixtures, null, 2));
  console.log(`\n[seed] Fixtures written to ${out}`);
  console.log('[seed] Run the probe:  node scripts/mt-test/isolation-probe.js --fixtures ' + out);

  await closeAll();
}

async function cleanup() {
  const file = arg('cleanup');
  const fixtures = JSON.parse(fs.readFileSync(file, 'utf8'));

  await connectDB();
  console.log(`[cleanup] Removing ${fixtures.tenants.length} test tenants...`);

  for (const tenant of fixtures.tenants) {
    try {
      await offboardTenant(tenant.tenantId);
      console.log(`  ✓ offboarded ${tenant.slug}`);
    } catch (err) {
      console.warn(`  ! ${tenant.slug}: ${err.message}`);
    }
  }

  // offboardTenant leaves the organizations row (marked offboarded) by design;
  // test tenants should disappear completely.
  const control = getControlDb();
  const ids = fixtures.tenants.map((t) => new mongoose.Types.ObjectId(t.tenantId));
  await control.collection('organizations').deleteMany({ _id: { $in: ids } });
  await control.collection('platform_events').deleteMany({ tenantId: { $in: ids } });
  console.log('[cleanup] Control-plane rows removed.');

  await closeAll();
}

(async () => {
  try {
    if (arg('cleanup')) await cleanup();
    else await seed();
    process.exit(0);
  } catch (err) {
    console.error('[seed] FAILED:', err.message);
    console.error(err.stack);
    process.exit(1);
  }
})();
