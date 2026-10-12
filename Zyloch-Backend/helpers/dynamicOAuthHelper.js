const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const MicrosoftStrategy = require('passport-microsoft').Strategy;
const { getTenantModels } = require('../db/tenantModels');
const { loginMember, MEMBER_LOGIN_ERRORS } = require('../services/authRouting');
const { getOAuthCallbackUrl } = require('../utils/validation');

/**
 * Read a provider's OAuth credentials from the tenant's tenant_settings doc.
 * @param {string} orgId  tenantId (== organization _id)
 * @param {'google'|'microsoft'} provider
 */
async function configureProviderStrategy(orgId, provider) {
  try {
    const models = getTenantModels(orgId);
    const settings = await models.TenantSettings.findOne({ tenantId: orgId }).lean();
    const cfg = settings?.oauth?.[provider];
    if (!cfg || !cfg.enabled) return {};

    return {
      clientID: cfg.clientId,
      clientSecret: cfg.clientSecret,
      // Normalised rather than used verbatim (from main): the callback must be the
      // URL we derive for this provider, so a stored value cannot redirect the
      // OAuth flow somewhere else.
      callbackURL: getOAuthCallbackUrl(provider, cfg.redirectUri),
      orgId,
    };
  } catch (error) {
    console.error(`Error configuring ${provider} strategy:`, error.message);
    return {};
  }
}

function buildVerifyCallback(provider) {
  return async (req, accessToken, refreshToken, params, profile, done) => {
    try {
      const providerId = profile.id;
      const email =
        profile.emails?.[0]?.value || profile.userPrincipalName || profile._json?.email;
      const name = profile.displayName;
      const avatar_url = profile.photos?.[0]?.value;

      if (!email) {
        return done(new Error(`${provider} account must have an email`), false);
      }

      const tokenExpiry = params.expires_in
        ? new Date(Date.now() + params.expires_in * 1000)
        : null;

      // On the callback the provider echoes `state`, which is where the orgId
      // actually arrives; the query spellings are the pre-redirect fallbacks.
      const orgId = req.query.state || req.query.org_id || req.query.orgId;

      const { user, tenantId } = await loginMember({
        provider,
        providerId,
        providerData: { login: email.split('@')[0], email, name, avatar_url },
        tokens: { accessToken, refreshToken, tokenExpiry },
        tenantId: orgId,
      });

      return done(null, { user, tenantId });
    } catch (error) {
      console.error(`${provider} Strategy Error:`, error.message);
      return done(error, false);
    }
  };
}

/**
 * Middleware that builds a per-organization passport strategy on the fly using
 * tenant-specific OAuth credentials, then authenticates the request.
 */
async function handleDynamicOAuth(req, res, next, provider) {
  try {
    // `org_id` is the current spelling; `orgId` is accepted so invite links and
    // bookmarks issued before the rename keep working.
    const orgId = req.query.org_id || req.query.orgId || req.query.state;
    if (!orgId) {
      return next();
    }

    const strategyName = `${provider}-${orgId}`;
    const config = await configureProviderStrategy(orgId, provider);

    if (passport._strategy(strategyName)) {
      passport.unuse(strategyName);
    }

    const scope = provider === 'google' ? ['profile', 'email'] : ['user.read'];
    const StrategyCtor = provider === 'google' ? GoogleStrategy : MicrosoftStrategy;

    const strategyOptions = {
      clientID: config.clientID,
      clientSecret: config.clientSecret,
      callbackURL: config.callbackURL,
      scope,
      passReqToCallback: true,
    };
    if (provider === 'microsoft') {
      strategyOptions.tenant = process.env.MICROSOFT_TENANT || 'common';
    }

    passport.use(strategyName, new StrategyCtor(strategyOptions, buildVerifyCallback(provider)));

    const authenticateOptions = {
      scope,
      session: false,
      state: orgId,
      failureRedirect: `${process.env.FRONTEND_URL}/login?error=${provider}_auth_failed`,
    };
    if (provider === 'google') {
      authenticateOptions.accessType = 'offline';
      authenticateOptions.prompt = 'consent';
    }

    return passport.authenticate(strategyName, authenticateOptions, (err, authResult) => {
      if (err) {
        console.error(`${provider} authentication error:`, err.message);
        // Membership decisions (no invite, deactivated, inactive org) are expected
        // outcomes of a browser redirect, not server faults — send the user back to
        // the login page with a code it can explain (MT-02.1).
        if (err.code && Object.values(MEMBER_LOGIN_ERRORS).includes(err.code)) {
          return res.redirect(`${process.env.FRONTEND_URL}/login?error=${err.code}`);
        }
        return next(err);
      }
      if (!authResult || !authResult.user) {
        return res.redirect(`${process.env.FRONTEND_URL}/login?error=${provider}_auth_failed`);
      }
      req.user = authResult.user;
      req.tenantId = String(authResult.tenantId);
      next();
    })(req, res, next);
  } catch (error) {
    console.error('Dynamic OAuth Error:', error.message);
    next(error);
  }
}

module.exports = { handleDynamicOAuth };
