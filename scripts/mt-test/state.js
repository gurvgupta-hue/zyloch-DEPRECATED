/* Read-only inventory of control plane + tenant DBs. */
const { MongoClient } = require('/app/node_modules/mongodb');

(async () => {
  const c = new MongoClient(process.env.MONGO_URI);
  await c.connect();
  const ctl = c.db('zyloch_control');

  console.log('=== organizations ===');
  for (const o of await ctl.collection('organizations').find({}).toArray()) {
    console.log(`  ${o._id} | ${o.provisionStatus} | domain=${o.domain} | name=${o.name} | admin=${o.adminUserId}`);
  }

  const idents = await ctl.collection('auth_identities').find({}).toArray();
  console.log(`=== auth_identities: ${idents.length}`);
  for (const a of idents) {
    console.log(`  ${a.provider} ${a.providerId} tenant=${a.tenantId} user=${a.userId} ${a.email}`);
  }

  const inst = await ctl.collection('installation_index').find({}).toArray();
  console.log(`=== installation_index: ${inst.length}`);
  for (const i of inst) console.log(`  ${i.githubInstallationId} -> tenant ${i.tenantId}`);

  const lic = await ctl.collection('tenant_licenses').find({}).toArray();
  console.log(`=== tenant_licenses: ${lic.length}`);
  for (const l of lic) console.log(`  tenant=${l.tenantId} plan=${l.planId} status=${l.status}`);

  console.log('=== tenant DBs ===');
  const ls = await c.db('admin').admin().listDatabases({ nameOnly: true });
  for (const d of ls.databases.filter((x) => x.name.startsWith('zyloch_tenant_'))) {
    const db = c.db(d.name);
    const counts = {};
    for (const col of await db.listCollections().toArray()) {
      counts[col.name] = await db.collection(col.name).countDocuments();
    }
    console.log(`  ${d.name}: ${JSON.stringify(counts)}`);
    for (const u of await db.collection('users').find({}).toArray().catch(() => [])) {
      console.log(`     user ${u._id} ${u.email} role=${u.role} login=${u.login} active=${u.isActive}`);
    }
  }
  await c.close();
})().catch((e) => { console.error('ERR', e.message); process.exit(1); });
