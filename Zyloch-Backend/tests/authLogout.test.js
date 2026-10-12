const { afterEach, describe, it } = require("node:test");
const assert = require("node:assert/strict");
const Module = require("node:module");

/**
 * Logout + GitHub-login behaviour (originally from main #368), rewritten for
 * Strategy C.
 *
 * What changed and why:
 *  - There is no global `models/user`. A user lives in its tenant's database, so
 *    the stubs here are `db/tenantModels` / `db/controlModels`.
 *  - The logout redirect used to look the org up via `User.organizationId`. The
 *    session JWT now carries `tenantId` (the canonical org id), so no DB read is
 *    needed for it.
 *  - The stored OAuth token moved from `User.oauthAccessToken` to the matching
 *    entry in `User.identities`.
 *  - main's "domain -> SSO organization" gate on GitHub login is deliberately
 *    gone; the last suite pins the replacement behaviour instead.
 */

const originalFrontendUrl = process.env.FRONTEND_URL;

afterEach(() => {
  if (originalFrontendUrl === undefined) {
    delete process.env.FRONTEND_URL;
  } else {
    process.env.FRONTEND_URL = originalFrontendUrl;
  }
});

function loadController({
  decoded,
  verifyError,
  onClearCookie,
  onUpdateUser,
  onSetCookie,
  loginGithubAdmin,
  axiosStub,
}) {
  const controllerPath = require.resolve("../controllers/auth");
  const originalLoad = Module._load;

  Module._load = function loadMock(request, parent, isMain) {
    if (request === "axios") return axiosStub || {};
    if (request === "../utils/jwt") {
      return {
        signSession: () => "signed-session",
        buildSessionPayload: (payload) => payload,
        verifySession: () => {
          if (verifyError) throw verifyError;
          return decoded;
        },
      };
    }
    if (request === "../helpers/cookieHelper") {
      return {
        setAuthCookie: (...args) => onSetCookie?.(...args),
        clearAuthCookie: (...args) => onClearCookie?.(...args),
      };
    }
    if (request === "../services/authRouting") {
      return {
        loginGithubAdmin:
          loginGithubAdmin ||
          (async () => ({
            user: { _id: "github-user-1", email: "member@example.com", role: "admin" },
            tenantId: "tenant-abc",
          })),
      };
    }
    if (request === "../db/controlModels") {
      return { getControlModels: () => ({}) };
    }
    if (request === "../db/tenantModels") {
      return {
        getTenantModels: (tenantId) => ({
          User: {
            updateOne: async (filter, update) => {
              onUpdateUser?.(tenantId, filter, update);
              return { acknowledged: true };
            },
          },
        }),
      };
    }
    if (request === "../helpers/oauthHelpers") {
      return { refreshGoogleToken: () => {}, refreshMicrosoftToken: () => {} };
    }
    return originalLoad.call(this, request, parent, isMain);
  };

  try {
    delete require.cache[controllerPath];
    return require(controllerPath);
  } finally {
    Module._load = originalLoad;
    delete require.cache[controllerPath];
  }
}

function makeResponse() {
  let payload;
  let redirectUrl;
  return {
    json: (data) => { payload = data; },
    redirect: (url) => { redirectUrl = url; },
    get payload() { return payload; },
    get redirectUrl() { return redirectUrl; },
  };
}

const githubAxiosStub = {
  post: async () => ({ data: { access_token: "github-access-token" } }),
  get: async (url) => {
    if (url.endsWith("/emails")) {
      return { data: [{ email: "member@example.com", primary: true, verified: true }] };
    }
    return {
      data: {
        id: 123,
        login: "member",
        name: "Example Member",
        avatar_url: "https://example.com/avatar.png",
        type: "User",
      },
    };
  },
};

describe("auth logout controller", () => {
  for (const provider of ["google", "microsoft"]) {
    it(`returns the organization login page for ${provider}`, async () => {
      process.env.FRONTEND_URL = "https://app.zyloch.test";
      const { logout } = loadController({
        decoded: { userId: "user-1", provider, tenantId: "org-123" },
      });
      const response = makeResponse();

      await logout(
        { cookies: { authToken: "session-token" } },
        response,
        (error) => { throw error; },
      );

      assert.equal(response.payload.success, true);
      assert.equal(
        response.payload.redirectUrl,
        "https://app.zyloch.test/login?orgId=org-123&loggedOut=1",
      );
    });
  }

  it("returns the standard login page for GitHub", async () => {
    process.env.FRONTEND_URL = "https://app.zyloch.test";
    const { logout } = loadController({
      decoded: { userId: "user-1", provider: "github", tenantId: "org-123" },
    });
    const response = makeResponse();

    await logout(
      { cookies: { authToken: "session-token" } },
      response,
      (error) => { throw error; },
    );

    assert.equal(
      response.payload.redirectUrl,
      "https://app.zyloch.test/login?loggedOut=1",
    );
  });

  it("clears the cookie and removes the stored OAuth tokens from the tenant DB", async () => {
    process.env.FRONTEND_URL = "https://app.zyloch.test";
    let clearedCookie;
    let updateArguments;
    const { logout } = loadController({
      decoded: { userId: "user-1", provider: "google", tenantId: "org-123" },
      onClearCookie: (response, name) => { clearedCookie = { response, name }; },
      onUpdateUser: (tenantId, filter, update) => {
        updateArguments = { tenantId, filter, update };
      },
    });
    const response = makeResponse();

    await logout(
      { cookies: { authToken: "session-token" } },
      response,
      (error) => { throw error; },
    );

    // The write must land in the caller's own tenant database.
    assert.equal(updateArguments.tenantId, "org-123");
    assert.deepEqual(updateArguments.filter, { _id: "user-1" });
    assert.deepEqual(updateArguments.update, {
      $unset: {
        "identities.$[].accessToken": "",
        "identities.$[].refreshToken": "",
        "identities.$[].tokenExpiry": "",
      },
    });
    assert.deepEqual(clearedCookie, { response, name: "authToken" });
  });

  it("succeeds and clears the cookie when the session has expired", async () => {
    process.env.FRONTEND_URL = "https://app.zyloch.test";
    const expiredError = new Error("jwt expired");
    expiredError.name = "TokenExpiredError";
    let clearedCookie;
    const { logout } = loadController({
      verifyError: expiredError,
      onClearCookie: (response, name) => { clearedCookie = { response, name }; },
    });
    const response = makeResponse();

    await logout(
      { cookies: { authToken: "expired-session-token" } },
      response,
      (error) => { throw error; },
    );

    assert.equal(response.payload.success, true);
    assert.equal(
      response.payload.redirectUrl,
      "https://app.zyloch.test/login?loggedOut=1",
    );
    assert.deepEqual(clearedCookie, { response, name: "authToken" });
  });

  it("succeeds when the authentication cookie is already absent", async () => {
    process.env.FRONTEND_URL = "https://app.zyloch.test";
    const { logout } = loadController({});
    const response = makeResponse();

    await logout({ cookies: {} }, response, (error) => { throw error; });

    assert.equal(response.payload.success, true);
    assert.equal(
      response.payload.redirectUrl,
      "https://app.zyloch.test/login?loggedOut=1",
    );
  });
});

describe("GitHub login tenant routing (Strategy C)", () => {
  it("routes the login through loginGithubAdmin and issues a tenant-scoped session", async () => {
    process.env.FRONTEND_URL = "https://app.zyloch.test";
    let routedWith;
    let cookie;
    const { oauthCallback } = loadController({
      axiosStub: githubAxiosStub,
      loginGithubAdmin: async (args) => {
        routedWith = args;
        return {
          user: { _id: "github-user-1", email: "member@example.com", role: "admin" },
          tenantId: "tenant-abc",
        };
      },
      onSetCookie: (response, name, value) => { cookie = { response, name, value }; },
    });
    const response = makeResponse();

    await oauthCallback(
      { query: { code: "github-code" } },
      response,
      (error) => { throw error; },
    );

    assert.equal(String(routedWith.providerId), "123");
    assert.equal(routedWith.providerData.email, "member@example.com");
    assert.deepEqual(cookie, {
      response,
      name: "authToken",
      value: "signed-session",
    });
    assert.equal(response.redirectUrl, "https://app.zyloch.test/login/callback");
  });

  it("does not route a GitHub login by email domain", async () => {
    // Replaces main's "same-domain SSO organization" redirect. Under Strategy C
    // `organizations.domain` is informational and never decides tenancy, so two
    // people sharing an email domain get independent tenants rather than one
    // being pushed into the other's organization or locked out.
    process.env.FRONTEND_URL = "https://app.zyloch.test";
    let loginCalled = false;
    const { oauthCallback } = loadController({
      axiosStub: githubAxiosStub,
      loginGithubAdmin: async () => {
        loginCalled = true;
        return {
          user: { _id: "github-user-1", email: "member@example.com", role: "admin" },
          tenantId: "tenant-abc",
        };
      },
    });
    const response = makeResponse();

    await oauthCallback(
      { query: { code: "github-code" } },
      response,
      (error) => { throw error; },
    );

    assert.equal(loginCalled, true);
    assert.equal(response.redirectUrl, "https://app.zyloch.test/login/callback");
    assert.ok(!String(response.redirectUrl).includes("github_login_disabled_for_sso"));
  });

  it("rejects a GitHub account with no verified email", async () => {
    process.env.FRONTEND_URL = "https://app.zyloch.test";
    const { oauthCallback } = loadController({
      axiosStub: {
        post: async () => ({ data: { access_token: "github-access-token" } }),
        get: async (url) => {
          if (url.endsWith("/emails")) {
            return { data: [{ email: "member@example.com", primary: true, verified: false }] };
          }
          return { data: { id: 123, login: "member", type: "User" } };
        },
      },
      loginGithubAdmin: async () => {
        throw new Error("must not reach tenant provisioning without a verified email");
      },
    });
    const response = makeResponse();

    let forwardedError;
    await oauthCallback(
      { query: { code: "github-code" } },
      response,
      (error) => { forwardedError = error; },
    );

    assert.ok(forwardedError, "expected the callback to reject the login");
    assert.match(String(forwardedError.message), /verified email/i);
  });
});
