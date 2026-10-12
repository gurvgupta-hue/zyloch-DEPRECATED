const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const createError = require('../utils/createError');

const TENANT_A = '674a1b2c3d4e5f6789012345';
const TENANT_B = '674a1b2c3d4e5f6789012346';
const INSTALL_ID = 9001;

const installationA = {
  installationId: INSTALL_ID,
  account: { id: 42, login: 'acme-org', type: 'Organization' },
};

describe('scans controller tenant scoping', () => {
  let tenantScope;
  let ghappClient;
  let licenseLimits;
  let scansController;
  let originalAssert;
  let originalGhappRequest;
  let originalAssertScan;
  let originalRecordScan;

  beforeEach(() => {
    process.env.GHAPP_S2S_API_KEY = 'test-service-key';
    process.env.SCAN_API_URL = 'http://policy-scanner:8000';

    tenantScope = require('../helpers/tenantScope');
    ghappClient = require('../helpers/ghappClient');
    originalAssert = tenantScope.assertInstallationBelongsToTenant;
    originalGhappRequest = ghappClient.ghappRequest;

    delete require.cache[require.resolve('../services/licenseLimits')];
    delete require.cache[require.resolve('../controllers/scans')];
    licenseLimits = require('../services/licenseLimits');
    originalAssertScan = licenseLimits.assertScanCapacity;
    originalRecordScan = licenseLimits.recordScanTriggered;
    licenseLimits.assertScanCapacity = async () => ({ limit: 100, current: 0 });
    licenseLimits.recordScanTriggered = async () => {};

    scansController = require('../controllers/scans');
  });

  afterEach(() => {
    tenantScope.assertInstallationBelongsToTenant = originalAssert;
    ghappClient.ghappRequest = originalGhappRequest;
    if (licenseLimits) {
      licenseLimits.assertScanCapacity = originalAssertScan;
      licenseLimits.recordScanTriggered = originalRecordScan;
    }
    delete require.cache[require.resolve('../controllers/scans')];
    delete require.cache[require.resolve('../services/licenseLimits')];
    delete process.env.GHAPP_S2S_API_KEY;
    delete process.env.SCAN_API_URL;
  });

  it('triggerScan returns 403 for cross-tenant installation', async () => {
    tenantScope.assertInstallationBelongsToTenant = async (_id, tenantId) => {
      if (String(tenantId) === TENANT_B) {
        throw createError(403, 'Installation does not belong to your organization');
      }
      return installationA;
    };

    const req = {
      tenant: { id: TENANT_B },
      tenantId: TENANT_B,
      body: {
        installation_id: String(INSTALL_ID),
        org_name: 'acme-org',
        repo_name: 'api',
      },
    };

    let err;
    await scansController.triggerScan(req, { json: () => {} }, (e) => {
      err = e;
    });

    assert.equal(err?.statusCode, 403);
  });

  it('triggerScan returns 403 when monthly scan license limit is reached', async () => {
    tenantScope.assertInstallationBelongsToTenant = async () => installationA;
    licenseLimits.assertScanCapacity = async () => {
      throw Object.assign(
        createError(403, 'License limit exceeded for maxScansPerMonth: 100/100'),
        { code: 'LICENSE_LIMIT_EXCEEDED', limitKey: 'maxScansPerMonth' }
      );
    };
    delete require.cache[require.resolve('../controllers/scans')];
    scansController = require('../controllers/scans');

    const req = {
      tenant: { id: TENANT_A },
      tenantId: TENANT_A,
      license: {
        active: true,
        // `scanners` is required since scan triggering became entitlement-gated (MT-05.2).
        entitlements: { maxScansPerMonth: 100, scanners: ['all'] },
      },
      body: {
        installation_id: String(INSTALL_ID),
        org_name: 'acme-org',
        repo_name: 'api',
      },
    };

    let err;
    await scansController.triggerScan(req, { json: () => {} }, (e) => {
      err = e;
    });

    assert.equal(err?.statusCode, 403);
    assert.equal(err?.code, 'LICENSE_LIMIT_EXCEEDED');
  });

  it('triggerScan proxies to GHAPP with service auth payload', async () => {
    tenantScope.assertInstallationBelongsToTenant = async () => installationA;

    let captured;
    let recorded = false;
    ghappClient.ghappRequest = async (method, path, options) => {
      captured = { method, path, options };
      return { message: 'Scan initiated' };
    };
    licenseLimits.recordScanTriggered = async () => {
      recorded = true;
    };
    delete require.cache[require.resolve('../controllers/scans')];
    scansController = require('../controllers/scans');

    const req = {
      tenant: { id: TENANT_A },
      tenantId: TENANT_A,
      license: {
        active: true,
        // `scanners` is required since scan triggering became entitlement-gated (MT-05.2).
        entitlements: { maxScansPerMonth: 100, scanners: ['all'] },
      },
      body: {
        installationId: String(INSTALL_ID),
        org_name: 'acme-org',
        repo_name: 'api',
        branch: 'main',
        scan_type: 'docker',
      },
    };

    let body;
    await scansController.triggerScan(
      req,
      { json: (data) => { body = data; } },
      () => {}
    );

    assert.equal(captured.method, 'POST');
    assert.equal(captured.path, '/scan');
    assert.deepEqual(captured.options.data, {
      installation_id: String(INSTALL_ID),
      org_name: 'acme-org',
      repo_name: 'api',
      branch: 'main',
      scan_type: 'docker',
      // Entitled scanner set forwarded so GHAPP cannot widen the plan (MT-05.2).
      allowed_scan_types: ['docker'],
    });
    assert.equal(body.message, 'Scan initiated');
    assert.equal(recorded, true);
  });

  it('listScans filters results to req.tenant.id and drops unstamped scans', async () => {
    tenantScope.assertInstallationBelongsToTenant = async () => installationA;

    ghappClient.ghappRequest = async () => ({
      scans: [
        { scan_id: 's1', scan_metadata: { tenantId: TENANT_A } },
        { scan_id: 's2', scan_metadata: { tenantId: TENANT_B } },
        // No tenant stamp. Previously returned to whoever asked; now dropped (MT-09.1).
        { scan_id: 's3', scan_metadata: { organization: 'acme-org' } },
      ],
    });

    const req = {
      tenant: { id: TENANT_A },
      query: { installationId: String(INSTALL_ID) },
    };

    let body;
    await scansController.listScans(
      req,
      { json: (data) => { body = data; } },
      () => {}
    );

    assert.equal(body.total_count, 1);
    assert.deepEqual(body.scans.map((s) => s.scan_id), ['s1']);
  });

  it('getScanById blocks scan owned by another tenant', async () => {
    tenantScope.assertInstallationBelongsToTenant = async () => installationA;

    ghappClient.ghappRequest = async () => ({
      scan_id: 'scan-x',
      scan_metadata: { tenantId: TENANT_B },
    });

    const req = {
      tenant: { id: TENANT_A },
      params: { scanId: 'scan-x' },
      query: { installationId: String(INSTALL_ID) },
    };

    let err;
    await scansController.getScanById(req, { json: () => {} }, (e) => {
      err = e;
    });

    assert.equal(err?.statusCode, 403);
  });
  // --- scan-request groups (iac / terraform) ---
  //
  // Regression: the UI sends `iac` for the IaC page and `terraform` for the
  // Terraform view. Both are groups GHAPP expands itself, but the entitlement
  // resolver only knew individual scanner keys and rejected them outright with
  // "Unknown scan type: iac".

  it('resolveEntitledScanRequest accepts the iac group and narrows it to the plan', () => {
    const { resolveEntitledScanRequest } = scansController;

    const full = resolveEntitledScanRequest('iac', { scanners: ['all'] });
    assert.equal(full.scanType, 'iac');
    assert.ok(full.allowedScanTypes.includes('docker'));
    assert.ok(full.allowedScanTypes.includes('cloudformation'));

    // A partial plan must narrow the group, not widen it.
    const partial = resolveEntitledScanRequest('iac', {
      scanners: ['docker', 'kubernetes', 'sbom'],
    });
    assert.equal(partial.scanType, 'iac');
    assert.deepEqual(partial.allowedScanTypes, ['docker', 'kubernetes']);
    assert.ok(!partial.allowedScanTypes.includes('sbom'), 'sbom is not an IaC scanner');
  });

  it('resolveEntitledScanRequest accepts the terraform group', () => {
    const r = scansController.resolveEntitledScanRequest('terraform', { scanners: ['all'] });
    assert.equal(r.scanType, 'terraform');
    assert.deepEqual(r.allowedScanTypes, [
      'terraform_aws',
      'terraform_azure',
      'terraform_gcp',
    ]);
  });

  it('resolveEntitledScanRequest rejects a group with no entitled members', () => {
    let err;
    try {
      scansController.resolveEntitledScanRequest('iac', { scanners: ['sbom'] });
    } catch (e) {
      err = e;
    }
    assert.equal(err?.statusCode, 403);
    assert.match(err.message, /not included in your plan/i);
  });

  it('resolveEntitledScanRequest still rejects a genuinely unknown scan type', () => {
    let err;
    try {
      scansController.resolveEntitledScanRequest('not-a-scanner', { scanners: ['all'] });
    } catch (e) {
      err = e;
    }
    assert.equal(err?.statusCode, 400);
    assert.match(err.message, /Unknown scan type/);
  });

  it('triggerScan forwards the iac group with an entitlement-narrowed allow list', async () => {
    tenantScope.assertInstallationBelongsToTenant = async () => installationA;
    let seen;
    ghappClient.ghappRequest = async (method, path, options) => {
      seen = options.data;
      return { status: 'started' };
    };

    const req = {
      tenant: { id: TENANT_A },
      tenantId: TENANT_A,
      license: { active: true, entitlements: { scanners: ['docker', 'bicep'], maxScansPerMonth: 100 } },
      body: {
        installation_id: String(INSTALL_ID),
        org_name: 'acme-org',
        repo_name: 'api',
        scan_type: 'iac',
      },
    };

    await scansController.triggerScan(req, { json: () => {} }, (e) => { throw e; });

    assert.equal(seen.scan_type, 'iac');
    assert.deepEqual(seen.allowed_scan_types, ['docker', 'bicep']);
  });

  // --- AI autofix (main #363/#376) behind the tenant boundary ---

  it('requestAutofix returns 403 for a cross-tenant installation', async () => {
    tenantScope.assertInstallationBelongsToTenant = async (_id, tenantId) => {
      if (String(tenantId) === TENANT_B) {
        throw createError(403, 'Installation does not belong to your organization');
      }
      return installationA;
    };
    let forwarded = false;
    ghappClient.ghappRequest = async () => {
      forwarded = true;
      return {};
    };

    const req = {
      tenant: { id: TENANT_B },
      tenantId: TENANT_B,
      body: { installationId: String(INSTALL_ID), description: 'x', code_block: 'y' },
    };

    let err;
    await scansController.requestAutofix(req, { json: () => {} }, (e) => { err = e; });

    assert.equal(err?.statusCode, 403);
    assert.equal(forwarded, false, 'must not reach the model gateway');
  });

  it('requestAutofix rejects a missing installationId', async () => {
    tenantScope.assertInstallationBelongsToTenant = async () => installationA;

    const req = {
      tenant: { id: TENANT_A },
      tenantId: TENANT_A,
      body: { description: 'x', code_block: 'y' },
    };

    let err;
    await scansController.requestAutofix(req, { json: () => {} }, (e) => { err = e; });

    assert.equal(err?.statusCode, 400);
  });

  it('requestAutofix forwards the tenant-checked installation id to GHAPP', async () => {
    tenantScope.assertInstallationBelongsToTenant = async () => installationA;
    let seen;
    ghappClient.ghappRequest = async (method, path, options) => {
      seen = { method, path, data: options.data };
      return { status: 'completed', content: 'fix' };
    };

    const req = {
      tenant: { id: TENANT_A },
      tenantId: TENANT_A,
      body: {
        installationId: String(INSTALL_ID),
        description: 'Bucket is public',
        code_block: 'resource "aws_s3_bucket" {}',
        policy_code: 'AWS-SEC-001',
      },
    };

    let payload;
    await scansController.requestAutofix(req, { json: (d) => { payload = d; } }, (e) => { throw e; });

    assert.equal(seen.method, 'POST');
    assert.equal(seen.path, '/scans/ai/autofix');
    assert.equal(seen.data.installation_id, String(INSTALL_ID));
    assert.equal(seen.data.policy_code, 'AWS-SEC-001');
    assert.equal(payload.status, 'completed');
  });

  it('createAutofixPr returns 403 for a cross-tenant installation', async () => {
    tenantScope.assertInstallationBelongsToTenant = async (_id, tenantId) => {
      if (String(tenantId) === TENANT_B) {
        throw createError(403, 'Installation does not belong to your organization');
      }
      return installationA;
    };
    let forwarded = false;
    ghappClient.ghappRequest = async () => {
      forwarded = true;
      return {};
    };

    const req = {
      tenant: { id: TENANT_B },
      tenantId: TENANT_B,
      body: {
        installationId: String(INSTALL_ID),
        repository: 'acme-org/api',
        file: 'main.tf',
        proposal: 'diff',
      },
    };

    let err;
    await scansController.createAutofixPr(req, { json: () => {} }, (e) => { err = e; });

    assert.equal(err?.statusCode, 403);
    assert.equal(forwarded, false, 'must not mint a GitHub token for another tenant');
  });

  it('createAutofixPr forwards a validated payload to GHAPP', async () => {
    tenantScope.assertInstallationBelongsToTenant = async () => installationA;
    let seen;
    ghappClient.ghappRequest = async (method, path, options) => {
      seen = { method, path, data: options.data };
      return { pr_url: 'https://github.com/acme-org/api/pull/1' };
    };

    const req = {
      tenant: { id: TENANT_A },
      tenantId: TENANT_A,
      body: {
        installationId: String(INSTALL_ID),
        repository: 'acme-org/api',
        branch: 'main',
        file: 'main.tf',
        code_block: 'old',
        proposal: 'new',
      },
    };

    let payload;
    await scansController.createAutofixPr(req, { json: (d) => { payload = d; } }, (e) => { throw e; });

    assert.equal(seen.path, '/scans/ai/autofix/pr');
    assert.equal(seen.data.installation_id, String(INSTALL_ID));
    assert.equal(seen.data.repository, 'acme-org/api');
    assert.match(payload.pr_url, /pull\/1/);
  });

  it('createAutofixPr rejects a missing repository', async () => {
    tenantScope.assertInstallationBelongsToTenant = async () => installationA;

    const req = {
      tenant: { id: TENANT_A },
      tenantId: TENANT_A,
      body: { installationId: String(INSTALL_ID), file: 'main.tf', proposal: 'diff' },
    };

    let err;
    await scansController.createAutofixPr(req, { json: () => {} }, (e) => { err = e; });

    assert.equal(err?.statusCode, 400);
  });

});

describe('ghappClient service auth', () => {
  let ghappClient;
  let originalAxios;

  beforeEach(() => {
    process.env.GHAPP_S2S_API_KEY = 'test-service-key';
    process.env.SCAN_API_URL = 'http://policy-scanner:8000';
    delete require.cache[require.resolve('../helpers/ghappClient')];
    ghappClient = require('../helpers/ghappClient');
    originalAxios = require('axios');
  });

  afterEach(() => {
    require.cache[require.resolve('axios')].exports = originalAxios;
    delete require.cache[require.resolve('../helpers/ghappClient')];
    delete process.env.GHAPP_S2S_API_KEY;
    delete process.env.SCAN_API_URL;
  });

  it('getGhappHeaders includes X-Zyloch-Service-Key', () => {
    const headers = ghappClient.getGhappHeaders();
    assert.equal(headers['X-Zyloch-Service-Key'], 'test-service-key');
  });

  it('ghappRequest fails when service key is missing', async () => {
    delete process.env.GHAPP_S2S_API_KEY;
    delete require.cache[require.resolve('../helpers/ghappClient')];
    const client = require('../helpers/ghappClient');

    let err;
    try {
      await client.ghappRequest('GET', '/scans');
    } catch (e) {
      err = e;
    }

    assert.equal(err?.statusCode, 500);
    assert.match(err.message, /not configured/i);
  });
});
