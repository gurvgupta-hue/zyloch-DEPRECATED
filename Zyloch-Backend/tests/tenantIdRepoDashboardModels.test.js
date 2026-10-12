const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const TENANT_A = '674a1b2c3d4e5f6789012345';

const repositoryData = require('../models/schemas/repositoryDataSchema');
const team = require('../models/schemas/teamSchema');
const teamMember = require('../models/schemas/teamMemberSchema');
const githubSecurityEvent = require('../models/schemas/githubSecurityEventSchema');
const installationSummaryJob = require('../models/schemas/installationSummaryJobSchema');

function assertTenantIdIndexed(schemaDef, label) {
  const path = schemaDef.schema.path('tenantId');
  assert.ok(path, `${label} must define tenantId`);
  assert.equal(path.isRequired, true, `${label}.tenantId must be required`);
  assert.equal(path.instance, 'ObjectId', `${label}.tenantId must be ObjectId`);

  const indexes = schemaDef.schema.indexes();
  const hasTenantIndex = indexes.some(([fields]) => fields.tenantId === 1);
  assert.ok(hasTenantIndex, `${label} must index tenantId`);
}

describe('KAN-38 tenantId on repo/dashboard models', () => {
  it('schemas declare required indexed tenantId', () => {
    assertTenantIdIndexed(repositoryData, 'RepositoryData');
    assertTenantIdIndexed(team, 'Team');
    assertTenantIdIndexed(teamMember, 'TeamMember');
    assertTenantIdIndexed(githubSecurityEvent, 'GitHubSecurityEvent');
    assertTenantIdIndexed(installationSummaryJob, 'InstallationSummaryJob');
  });

  it('ingestPatRequestWebhook requires tenantId and writes it on events', async () => {
    const { ingestPatRequestWebhook } = require('../helpers/securitySignalsHelper');

    const missing = await ingestPatRequestWebhook(
      { findOneAndUpdate: async () => ({}) },
      {
        action: 'created',
        installation: { id: 1, account: { id: 2, login: 'acme' } },
        organization: { id: 2, login: 'acme' },
        personal_access_token_request: { id: 'req-1' },
      },
      'delivery-1'
    );
    assert.equal(missing.inserted, 0);

    let captured;
    const SecurityEvent = {
      findOneAndUpdate: async (_filter, payload) => {
        captured = payload;
        return payload;
      },
    };

    const result = await ingestPatRequestWebhook(
      SecurityEvent,
      {
        action: 'created',
        installation: { id: 1, account: { id: 2, login: 'acme' } },
        organization: { id: 2, login: 'acme' },
        personal_access_token_request: { id: 'req-1', request_id: 'req-1' },
        sender: { id: '9', login: 'admin' },
      },
      'delivery-1',
      TENANT_A
    );

    assert.equal(result.inserted >= 1, true);
    assert.equal(String(captured.tenantId), TENANT_A);
  });

  it('ingestForkWebhook writes tenantId for external forks', async () => {
    const { ingestForkWebhook } = require('../helpers/securitySignalsHelper');

    let captured;
    const SecurityEvent = {
      findOneAndUpdate: async (_filter, payload) => {
        captured = payload;
        return payload;
      },
    };

    const result = await ingestForkWebhook(
      SecurityEvent,
      {
        installation: { id: 11, account: { id: 22, login: 'acme' } },
        organization: { id: 22, login: 'acme' },
        repository: { owner: { login: 'acme', id: 22 }, name: 'api', full_name: 'acme/api' },
        forkee: {
          owner: { login: 'outsider' },
          name: 'api',
          full_name: 'outsider/api',
          html_url: 'https://github.com/outsider/api',
          created_at: new Date().toISOString(),
        },
        sender: { id: '9', login: 'admin' },
      },
      'delivery-fork',
      TENANT_A
    );

    assert.equal(result.inserted, 1);
    assert.equal(String(captured.tenantId), TENANT_A);
    assert.equal(captured.signalType, 'external_org_fork');
  });
});
