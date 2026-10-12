const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');

const TENANT_A = '674a1b2c3d4e5f6789012345';
const LINKED_INSTALL = 9100;
const UNLINKED_INSTALL = 156569970;

const webhookPath = require.resolve('../controllers/webhook.js');
const authRoutingPath = require.resolve('../services/authRouting.js');
const controlModelsPath = require.resolve('../db/controlModels.js');
const tenantModelsPath = require.resolve('../db/tenantModels.js');
const summaryQueuePath = require.resolve('../queues/summaryQueue.js');
const ghappClientPath = require.resolve('../helpers/ghappClient.js');

const stub = (filename, exports) => {
  require.cache[filename] = { id: filename, filename, loaded: true, exports };
};

// push / pull_request are forwarded to the scan service, which needs a tenant to
// write results into. An installation with no tenant used to be forwarded anyway
// and rejected there, failing a request on both sides for every push.
describe('code-event webhooks (push / pull_request)', () => {
  let webhook;
  let forwarded;
  let platformEvents;
  let originalPost;
  const originals = new Map();

  beforeEach(() => {
    forwarded = [];
    platformEvents = [];

    [webhookPath, authRoutingPath, controlModelsPath, tenantModelsPath, summaryQueuePath, ghappClientPath]
      .forEach((p) => originals.set(p, require.cache[p]));

    stub(authRoutingPath, {
      getTenantByInstallationId: async (id) => (id === LINKED_INSTALL ? TENANT_A : null),
      resolveTenantByIdentity: async () => null,
    });
    stub(controlModelsPath, {
      getControlModels: () => ({
        PlatformEvent: { create: async (doc) => { platformEvents.push(doc); return doc; } },
      }),
    });
    stub(tenantModelsPath, { getTenantModels: (tenantId) => ({ tenantId: String(tenantId) }) });
    stub(summaryQueuePath, { add: async () => ({ id: 'bull-1' }) });
    stub(ghappClientPath, { getGhappBaseUrl: () => 'http://policy-scanner:8000' });

    const axios = require('axios');
    originalPost = axios.post;
    axios.post = async (url) => {
      forwarded.push(url);
      return { data: { message: 'Scan initiated' } };
    };

    delete require.cache[webhookPath];
    webhook = require('../controllers/webhook.js');
  });

  afterEach(() => {
    require('axios').post = originalPost;
    for (const [p, mod] of originals) {
      if (mod) require.cache[p] = mod;
      else delete require.cache[p];
    }
    originals.clear();
    delete require.cache[webhookPath];
  });

  async function deliver(event, body) {
    let statusCode;
    let responseBody;
    const res = {
      status: (code) => {
        statusCode = code;
        return { json: (data) => { responseBody = data; } };
      },
    };
    await webhook.handleWebhook(
      { headers: { 'x-github-event': event, 'x-github-delivery': 'del-1' }, body },
      res,
      (err) => { if (err) throw err; }
    );
    // Forwarding is fire-and-forget; let it settle before asserting.
    await new Promise((resolve) => setImmediate(resolve));
    return { statusCode, responseBody };
  }

  const pullRequest = (installationId) => ({
    installation: { id: installationId },
    repository: { name: 'zyloch', owner: { login: 'Secure-Code-dev' } },
    pull_request: { head: { ref: 'feature' } },
  });

  it('forwards a code event from a linked installation to the scan service', async () => {
    const { statusCode, responseBody } = await deliver('pull_request', pullRequest(LINKED_INSTALL));

    assert.equal(statusCode, 200);
    assert.equal(responseBody.message, 'Event forwarded to scan service');
    assert.deepEqual(forwarded, ['http://policy-scanner:8000/webhook/github']);
  });

  it('does not forward a code event from an unlinked installation', async () => {
    for (const event of ['push', 'pull_request']) {
      const { statusCode, responseBody } = await deliver(event, pullRequest(UNLINKED_INSTALL));
      assert.equal(statusCode, 200);
      assert.equal(responseBody.note, 'unlinked_installation');
    }

    assert.deepEqual(forwarded, []);
    assert.equal(platformEvents.length, 2);
    assert.equal(platformEvents[0].payload.installationId, UNLINKED_INSTALL);
    assert.equal(platformEvents[0].payload.githubEvent, 'push');
    assert.equal(platformEvents[0].payload.accountLogin, 'Secure-Code-dev');
  });

  it('does not forward a code event that carries no installation', async () => {
    const { responseBody } = await deliver('push', { repository: { name: 'zyloch' } });

    assert.equal(responseBody.note, 'unlinked_installation');
    assert.deepEqual(forwarded, []);
  });
});
