const crypto = require('crypto');
const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');

const verifyWebhook = require('../middleware/verifyWebhook');

const SECRET = 'test-webhook-secret';
const BODY = Buffer.from(JSON.stringify({ action: 'created' }));

function sign(body, secret = SECRET) {
  return 'sha256=' + crypto.createHmac('sha256', secret).update(body).digest('hex');
}

function run(req) {
  return new Promise((resolve) => {
    verifyWebhook(req, {}, (err) => resolve(err));
  });
}

function request({ signature, rawBody = BODY } = {}) {
  return {
    headers: signature ? { 'x-hub-signature-256': signature } : {},
    rawBody,
  };
}

let originalSecret;
let originalEnv;

beforeEach(() => {
  originalSecret = process.env.GITHUB_WEBHOOK_SECRET;
  originalEnv = process.env.NODE_ENV;
  process.env.GITHUB_WEBHOOK_SECRET = SECRET;
});

afterEach(() => {
  if (originalSecret === undefined) delete process.env.GITHUB_WEBHOOK_SECRET;
  else process.env.GITHUB_WEBHOOK_SECRET = originalSecret;
  if (originalEnv === undefined) delete process.env.NODE_ENV;
  else process.env.NODE_ENV = originalEnv;
});

describe('MT-04.2 webhook verification has no environment bypass', () => {
  it('still rejects a forged signature in development', async () => {
    process.env.NODE_ENV = 'development';
    const err = await run(request({ signature: sign(BODY, 'attacker-secret') }));
    assert.equal(err.statusCode, 401);
  });

  it('still requires a signature header in development', async () => {
    process.env.NODE_ENV = 'development';
    const err = await run(request());
    assert.equal(err.statusCode, 400);
  });

  it('still rejects a forged signature in test and production', async () => {
    for (const env of ['test', 'production']) {
      process.env.NODE_ENV = env;
      const err = await run(request({ signature: sign(BODY, 'attacker-secret') }));
      assert.equal(err.statusCode, 401, `expected 401 in NODE_ENV=${env}`);
    }
  });

  it('accepts a correctly signed payload', async () => {
    const err = await run(request({ signature: sign(BODY) }));
    assert.equal(err, undefined);
  });
});

describe('MT-04 webhook verification fails closed on misconfiguration', () => {
  it('rejects when the secret is unset rather than allowing through', async () => {
    delete process.env.GITHUB_WEBHOOK_SECRET;
    const err = await run(request({ signature: sign(BODY) }));
    assert.equal(err.statusCode, 500);
    assert.match(err.message, /not configured/i);
  });

  it('rejects when the raw body was not captured', async () => {
    const err = await run(request({ signature: sign(BODY), rawBody: null }));
    assert.equal(err.statusCode, 500);
  });

  it('rejects a body altered after signing', async () => {
    const signature = sign(BODY);
    const tampered = Buffer.from(JSON.stringify({ action: 'deleted' }));
    const err = await run(request({ signature, rawBody: tampered }));
    assert.equal(err.statusCode, 401);
  });
});

describe('MT-04.3 signature comparison is constant time', () => {
  const { signaturesMatch } = verifyWebhook;

  it('matches identical signatures', () => {
    assert.equal(signaturesMatch(sign(BODY), sign(BODY)), true);
  });

  it('rejects mismatched signatures of equal length', () => {
    assert.equal(signaturesMatch(sign(BODY), sign(BODY, 'other')), false);
  });

  it('rejects differing lengths without throwing', () => {
    assert.doesNotThrow(() => signaturesMatch('sha256=short', sign(BODY)));
    assert.equal(signaturesMatch('sha256=short', sign(BODY)), false);
  });

  it('rejects an empty or missing signature without throwing', () => {
    assert.equal(signaturesMatch('', sign(BODY)), false);
    assert.equal(signaturesMatch(undefined, sign(BODY)), false);
  });
});
