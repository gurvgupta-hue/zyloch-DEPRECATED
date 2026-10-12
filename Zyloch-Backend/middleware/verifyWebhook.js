const crypto = require('crypto');
const createError = require('../utils/createError');

/**
 * Constant-time comparison of two signature strings.
 *
 * `timingSafeEqual` throws on length mismatch, so compare lengths first — that
 * leak is harmless (signature length is fixed and public) while a byte-by-byte
 * `!==` on the digest itself is not (MT-04.3).
 */
function signaturesMatch(provided, expected) {
  const a = Buffer.from(String(provided));
  const b = Buffer.from(String(expected));
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

/**
 * Verify the GitHub webhook HMAC over the raw request body.
 *
 * Fails closed in every environment (MT-04.2). There is deliberately no
 * NODE_ENV=development bypass: this route is unauthenticated apart from the
 * signature, and a bypass that keys off an env var is one misconfigured deploy
 * away from accepting forged installation events. To exercise webhooks locally,
 * set GITHUB_WEBHOOK_SECRET and sign the payload (the GitHub CLI, `gh webhook
 * forward`, and smee.io all do this for you).
 */
module.exports = (req, res, next) => {
  const secret = process.env.GITHUB_WEBHOOK_SECRET;
  const signature = req.headers['x-hub-signature-256'];

  if (!secret) {
    console.error(
      '❌ GITHUB_WEBHOOK_SECRET is not configured — rejecting webhook. ' +
        'Set it to the secret configured on the GitHub App.'
    );
    return next(createError(500, 'Webhook verification is not configured'));
  }

  if (!signature) {
    return next(createError(400, 'Missing signature header'));
  }

  if (!req.rawBody) {
    console.error('❌ req.rawBody is missing. Ensure raw body middleware is used.');
    return next(createError(500, 'Raw body missing for signature verification'));
  }

  const expected =
    'sha256=' + crypto.createHmac('sha256', secret).update(req.rawBody).digest('hex');

  if (!signaturesMatch(signature, expected)) {
    console.error('❌ Invalid GitHub webhook signature');
    return next(createError(401, 'Invalid signature'));
  }

  next();
};

module.exports.signaturesMatch = signaturesMatch;
