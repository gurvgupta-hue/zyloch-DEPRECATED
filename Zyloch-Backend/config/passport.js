/**
 * Passport.js configuration.
 *
 * OAuth strategies are registered dynamically per-tenant (see
 * helpers/dynamicOAuthHelper.js) and authentication runs with `session: false`,
 * so passport sessions / (de)serialization are not used. We keep minimal
 * serialize/deserialize hooks only to satisfy passport's API surface.
 */

const passport = require('passport');

passport.serializeUser((user, done) => {
  done(null, user && user._id ? user._id.toString() : null);
});

passport.deserializeUser((id, done) => {
  // Sessions are disabled; nothing to rehydrate.
  done(null, false);
});

module.exports = passport;
