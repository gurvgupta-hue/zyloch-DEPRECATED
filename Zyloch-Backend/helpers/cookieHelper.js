/**
 * `Secure` must reflect actual transport, not deployment tier.
 *
 * Deriving it from NODE_ENV alone marked cookies Secure on stacks with no TLS
 * termination (e.g. the docker-compose setup, served over plain http:// on an
 * IP or hostname): the browser silently drops the Set-Cookie, login "succeeds"
 * but no cookie lands, and every next request 401s back to the login screen.
 *
 * So the protocol of the public callback URL decides, and `COOKIE_SECURE`
 * remains an explicit override for stacks where that URL does not describe the
 * transport the browser actually sees (e.g. TLS terminated at a proxy).
 */
function getCookieSecurityOptions() {
  const override = process.env.COOKIE_SECURE;
  let secure;

  if (override === "true" || override === "false") {
    secure = override === "true";
  } else {
    const publicUrl = process.env.OAUTH_REDIRECT_URI || process.env.FRONTEND_URL;
    secure = process.env.NODE_ENV === "production";

    if (publicUrl) {
      try {
        secure = new URL(publicUrl).protocol === "https:";
      } catch (_) {}
    }
  }

  return {
    secure,
    sameSite: secure ? "None" : "Lax",
  };
}

function setAuthCookie(res, name, token, options = {}) {
  const defaultOptions = {
    httpOnly: true,
    path: "/",
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    ...getCookieSecurityOptions(),
  };

  res.cookie(name, token, { ...defaultOptions, ...options });
}

function clearAuthCookie(res, name) {
  res.clearCookie(name, {
    httpOnly: true,
    path: "/",
    ...getCookieSecurityOptions(),
  });
}

module.exports = { setAuthCookie, clearAuthCookie };
