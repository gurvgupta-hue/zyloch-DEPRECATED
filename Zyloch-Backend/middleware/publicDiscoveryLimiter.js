const rateLimit = require('express-rate-limit');

/**
 * Rate limiter for the one remaining unauthenticated pre-login endpoint (MT-02):
 *   GET /api/organization/:orgId/providers
 *
 * It must stay public — the login page renders the Google/Microsoft buttons from
 * it before a session exists — so the residual risk is bulk probing of which
 * organization ids exist. Joining a tenant is gated by an invite (see
 * loginMember), so this limiter is about customer-list harvesting, not access.
 *
 * The companion domain lookup (`GET /auth/resolve-org`) was removed outright: it
 * answered "is this company a Zyloch customer?" for anyone who asked, and a rate
 * limit only slows that down rather than closing it. Callers now arrive with
 * ?orgid= already on the invite link.
 *
 * Deliberately per-IP and generous enough that a shared office NAT never sees a 429.
 */
const publicDiscoveryLimiter = rateLimit({
  windowMs: Number(process.env.DISCOVERY_RATE_WINDOW_MS || 15 * 60 * 1000),
  max: Number(process.env.DISCOVERY_RATE_MAX || 30),
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    message: 'Too many organization lookups. Please try again shortly.',
  },
});

module.exports = publicDiscoveryLimiter;
