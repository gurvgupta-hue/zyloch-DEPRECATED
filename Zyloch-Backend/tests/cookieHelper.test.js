const { afterEach, describe, it } = require("node:test");
const assert = require("node:assert/strict");
const { setAuthCookie, clearAuthCookie } = require("../helpers/cookieHelper");

const originalEnvironment = {
  frontendUrl: process.env.FRONTEND_URL,
  nodeEnv: process.env.NODE_ENV,
  oauthRedirectUri: process.env.OAUTH_REDIRECT_URI,
};

afterEach(() => {
  restoreEnvironment("FRONTEND_URL", originalEnvironment.frontendUrl);
  restoreEnvironment("NODE_ENV", originalEnvironment.nodeEnv);
  restoreEnvironment("OAUTH_REDIRECT_URI", originalEnvironment.oauthRedirectUri);
});

function restoreEnvironment(name, value) {
  if (value === undefined) {
    delete process.env[name];
  } else {
    process.env[name] = value;
  }
}

function makeResponse() {
  const calls = {};
  return {
    cookie: (name, token, options) => { calls.cookie = { name, token, options }; },
    clearCookie: (name, options) => { calls.clearCookie = { name, options }; },
    calls,
  };
}

describe("authentication cookie options", () => {
  it("allows the cookie on an HTTP hostname callback", () => {
    process.env.NODE_ENV = "production";
    process.env.OAUTH_REDIRECT_URI =
      "http://admin-vm.secure-labs.io:5000/auth/github/callback";
    const response = makeResponse();

    setAuthCookie(response, "authToken", "session-token");

    assert.equal(response.calls.cookie.options.secure, false);
    assert.equal(response.calls.cookie.options.sameSite, "Lax");
  });

  it("uses a cross-site secure cookie for an HTTPS callback", () => {
    process.env.NODE_ENV = "development";
    process.env.OAUTH_REDIRECT_URI =
      "https://zyloch-beta.sandbox-secure-code.com/auth/github/callback";
    const response = makeResponse();

    setAuthCookie(response, "authToken", "session-token");

    assert.equal(response.calls.cookie.options.secure, true);
    assert.equal(response.calls.cookie.options.sameSite, "None");
  });

  it("uses matching security attributes when clearing the cookie", () => {
    process.env.OAUTH_REDIRECT_URI =
      "http://admin-vm.secure-labs.io:5000/auth/github/callback";
    const response = makeResponse();

    setAuthCookie(response, "authToken", "session-token");
    clearAuthCookie(response, "authToken");

    assert.equal(
      response.calls.clearCookie.options.secure,
      response.calls.cookie.options.secure,
    );
    assert.equal(
      response.calls.clearCookie.options.sameSite,
      response.calls.cookie.options.sameSite,
    );
  });
});