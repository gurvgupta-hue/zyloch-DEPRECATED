const {
  verifySession,
  buildSessionPayload,
  sessionClaimsStale,
  signSession,
} = require('../utils/jwt');
const createError = require('../utils/createError');
const { setAuthCookie } = require('../helpers/cookieHelper');
const { getTenantModels } = require('../db/tenantModels');
const { resolveTenantAccess } = require('../services/tenantAccess');

/**
 * Resolve tenant + user auth fields from JWT claims with DB fallback.
 * Role/org id prefer JWT (set at login); DB user.role is used when JWT is stale
 * and triggers a cookie refresh on the same request.
 */
function buildAuthContext({ session, user, tenantId }) {
  const id = String(tenantId);
  const role = session?.role || user.role;

  return {
    tenant: { id, role },
    userFields: {
      role,
      organizationId: id,
      tenantId: id,
    },
  };
}

/**
 * JWT authentication (cookie-based) + tenant resolution.
 *
 * Attaches:
 *   - req.tenant     { id, role }  — from JWT; role falls back to tenant DB user
 *   - req.tenantId   string        — same as req.tenant.id
 *   - req.user       includes organizationId (== tenantId) and role without per-route DB lookups
 *   - req.models     tenant-scoped Mongoose models
 *
 * One User.findById runs here per authenticated request (profile + stale-role check).
 * req.tenant.role / req.user.role come from JWT when the claim is current.
 */
async function auth(req, res, next) {
  try {
    const token = req.cookies?.authToken;
    if (!token) {
      return next(createError(401, 'Authentication required please sign in again.'));
    }

    // A cookie we cannot open is an unauthenticated request, not a server fault.
    // `verifySession` reports expiry, tampering and a failed decrypt (e.g. the
    // signing secret was rotated) all as a plain Error, so the name-based
    // branches in the catch below never matched and every one of them became a
    // 500. The frontend route guard only redirects to /login on 401/403, so that
    // left a browser holding a stale cookie stranded on a dead page with no way
    // to recover but clearing cookies by hand.
    let session;
    try {
      session = verifySession(token);
    } catch (err) {
      console.warn('Rejecting unreadable session cookie:', err.message);
      return next(createError(401, 'Session invalid or expired. Please sign in again.'));
    }

    if (!session || !session.userId) {
      console.error('Invalid session payload:', session);
      return next(createError(401, 'Invalid or tampered session data.'));
    }

    if (!session.tenantId) {
      return next(
        createError(403, 'Organization context required. Please sign in again with your organization.')
      );
    }

    req.tenantId = String(session.tenantId);

    // Organization standing + entitlements, resolved together (MT-05.4).
    // Checked before the user lookup so a suspended tenant costs one round trip.
    const { organization, license, standing } = await resolveTenantAccess(req.tenantId);
    if (!standing.allowed) {
      return next(
        Object.assign(createError(403, standing.message), { code: standing.code })
      );
    }
    req.organization = organization;
    req.license = license;

    // Only after the organization is known to exist. Compiling tenant models is
    // not the read-only act it looks like: Mongoose builds each model's indexes
    // on compile, and creating an index creates the collection, which creates the
    // database. Resolving models first meant every request bearing the id of a
    // deleted tenant — a stale cookie is enough — re-materialised that tenant's
    // database as a set of empty collections, moments before this code decided
    // the organization did not exist. Those ghost databases then outlive the
    // request with no `organizations` row to explain them.
    const models = getTenantModels(req.tenantId);
    req.models = models;

    const user = await models.User.findById(session.userId).select(
      '-identities.accessToken -identities.refreshToken'
    );
    if (!user) {
      console.error('User not found for session:', session.userId);
      return next(createError(401, 'User not found. Please log in again.'));
    }

    if (user.isActive === false) {
      return next(createError(403, 'Your account has been deactivated for this organization'));
    }

    if (sessionClaimsStale(session, { role: user.role })) {
      const refreshedToken = signSession(
        buildSessionPayload({
          userId: user._id,
          tenantId: req.tenantId,
          email: user.email,
          provider: session.provider || user.primaryIdentity?.provider,
          role: user.role,
        })
      );
      setAuthCookie(res, 'authToken', refreshedToken);
      session.role = user.role;
    }

    const { tenant, userFields } = buildAuthContext({
      session,
      user,
      tenantId: req.tenantId,
    });
    req.tenant = tenant;

    const githubIdentity = user.getIdentity('github');

    req.user = {
      id: user._id.toString(),
      email: user.email,
      name: user.name,
      avatar_url: user.avatar_url,
      provider: session.provider || user.primaryIdentity?.provider,
      login: githubIdentity?.providerData?.login || user.login || user.email.split('@')[0],
      githubId: githubIdentity?.providerId || user.githubId,
      iat: session.iat,
      exp: session.exp,
      hasGitHub: !!githubIdentity,
      ...userFields,
    };

    next();
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      console.warn('JWT expired for request:', req.originalUrl);
      return next(createError(401, 'Session expired. Please log in again.'));
    }
    if (err.name === 'JsonWebTokenError') {
      console.error('JWT verification failed:', err.message);
      return next(createError(401, 'Invalid authentication token.'));
    }
    console.error('Auth middleware critical error:', err.message);
    next(createError(500, 'Authentication middleware failure.'));
  }
}

auth.buildAuthContext = buildAuthContext;
module.exports = auth;
