const { describe, it, beforeEach, mock } = require("node:test");
const assert = require("node:assert/strict");

// ─── Mocks ───────────────────────────────────────────────────────────────────

// Minimal mock builder helpers
function makeUser(overrides = {}) {
  return {
    _id: "user-1",
    organizationId: "org-1",
    role: "admin",
    ...overrides,
  };
}

function makeOrg(overrides = {}) {
  return {
    _id: "org-1",
    name: "Test Org",
    policyConfigurations: {},
    isAdmin: (userId) => userId === "user-1",
    markModified: () => {},
    save: async () => {},
    ...overrides,
  };
}

function makeReq(overrides = {}) {
  return {
    cookies: { authToken: "valid-token" },
    body: {},
    ...overrides,
  };
}

function makeRes() {
  let payload;
  return {
    json: (data) => { payload = data; },
    get payload() { return payload; },
  };
}

// ─── Tests ───────────────────────────────────────────────────────────────────

describe("organization policy configuration controller", () => {
  // ── getPolicyConfigurations ───────────────────────────────────────────────

  describe("getPolicyConfigurations", () => {
    it("returns stored policyConfigurations and userRole on success", async () => {
      const storedConfig = {
        scanners: { secret_scanner: { policies: { openai_api_key: false } } },
      };

      const User = { findById: () => ({ select: async () => makeUser() }) };
      const Organization = {
        findById: () => ({
          select: async () => makeOrg({ policyConfigurations: storedConfig }),
        }),
      };
      const verifySession = () => ({ userId: "user-1" });
      const createError = (code, msg) => Object.assign(new Error(msg), { status: code });

      const controller = buildGetController({ User, Organization, verifySession, createError });

      const req = makeReq();
      const res = makeRes();
      let nextErr = null;
      await controller(req, res, (e) => { nextErr = e; });

      assert.equal(nextErr, null);
      assert.equal(res.payload.success, true);
      assert.deepEqual(res.payload.policyConfigurations, storedConfig);
      assert.equal(res.payload.userRole, "admin");
    });

    it("returns empty object when policyConfigurations is unset", async () => {
      const User = { findById: () => ({ select: async () => makeUser() }) };
      const Organization = {
        findById: () => ({
          select: async () => makeOrg({ policyConfigurations: undefined }),
        }),
      };
      const verifySession = () => ({ userId: "user-1" });
      const createError = (code, msg) => Object.assign(new Error(msg), { status: code });

      const controller = buildGetController({ User, Organization, verifySession, createError });

      const res = makeRes();
      await controller(makeReq(), res, () => {});

      assert.deepEqual(res.payload.policyConfigurations, {});
    });

    it("calls next with 404 when user is not found", async () => {
      const User = { findById: () => ({ select: async () => null }) };
      const Organization = { findById: () => ({ select: async () => makeOrg() }) };
      const verifySession = () => ({ userId: "user-1" });
      const createError = (code, msg) => Object.assign(new Error(msg), { status: code });

      const controller = buildGetController({ User, Organization, verifySession, createError });

      let nextErr = null;
      await controller(makeReq(), makeRes(), (e) => { nextErr = e; });

      assert.equal(nextErr.status, 404);
      assert.match(nextErr.message, /user not found/i);
    });

    it("calls next with 404 when user has no organizationId", async () => {
      const User = { findById: () => ({ select: async () => makeUser({ organizationId: null }) }) };
      const Organization = { findById: () => ({ select: async () => makeOrg() }) };
      const verifySession = () => ({ userId: "user-1" });
      const createError = (code, msg) => Object.assign(new Error(msg), { status: code });

      const controller = buildGetController({ User, Organization, verifySession, createError });

      let nextErr = null;
      await controller(makeReq(), makeRes(), (e) => { nextErr = e; });

      assert.equal(nextErr.status, 404);
      assert.match(nextErr.message, /not associated/i);
    });
  });

  // ── updatePolicyConfigurations ────────────────────────────────────────────

  describe("updatePolicyConfigurations", () => {
    it("saves policyConfigurations and returns success on valid admin request", async () => {
      const newConfig = {
        scanners: { terraform_gcp: { policies: { "GCP-SEC-VM-001": false } } },
      };

      let savedConfig = null;
      const org = makeOrg({
        save: async function () { savedConfig = this.policyConfigurations; },
      });

      const User = { findById: () => ({ select: async () => makeUser() }) };
      const Organization = { findById: async () => org };
      const verifySession = () => ({ userId: "user-1" });
      const createError = (code, msg) => Object.assign(new Error(msg), { status: code });

      const controller = buildUpdateController({ User, Organization, verifySession, createError });

      const res = makeRes();
      await controller(
        makeReq({ body: { policyConfigurations: newConfig } }),
        res,
        (e) => { throw e; }
      );

      assert.equal(res.payload.success, true);
      assert.deepEqual(savedConfig, newConfig);
    });

    it("calls next with 403 when caller is not the org admin", async () => {
      const org = makeOrg({ isAdmin: () => false });
      const User = { findById: () => ({ select: async () => makeUser() }) };
      const Organization = { findById: async () => org };
      const verifySession = () => ({ userId: "user-1" });
      const createError = (code, msg) => Object.assign(new Error(msg), { status: code });

      const controller = buildUpdateController({ User, Organization, verifySession, createError });

      let nextErr = null;
      await controller(
        makeReq({ body: { policyConfigurations: {} } }),
        makeRes(),
        (e) => { nextErr = e; }
      );

      assert.equal(nextErr.status, 403);
      assert.match(nextErr.message, /admin/i);
    });

    it("calls next with 400 when policyConfigurations is missing from body", async () => {
      const User = { findById: () => ({ select: async () => makeUser() }) };
      const Organization = { findById: async () => makeOrg() };
      const verifySession = () => ({ userId: "user-1" });
      const createError = (code, msg) => Object.assign(new Error(msg), { status: code });

      const controller = buildUpdateController({ User, Organization, verifySession, createError });

      let nextErr = null;
      await controller(makeReq({ body: {} }), makeRes(), (e) => { nextErr = e; });

      assert.equal(nextErr.status, 400);
      assert.match(nextErr.message, /required/i);
    });

    it("calls next with 404 when user is not found", async () => {
      const User = { findById: () => ({ select: async () => null }) };
      const Organization = { findById: async () => makeOrg() };
      const verifySession = () => ({ userId: "user-1" });
      const createError = (code, msg) => Object.assign(new Error(msg), { status: code });

      const controller = buildUpdateController({ User, Organization, verifySession, createError });

      let nextErr = null;
      await controller(
        makeReq({ body: { policyConfigurations: {} } }),
        makeRes(),
        (e) => { nextErr = e; }
      );

      assert.equal(nextErr.status, 404);
    });

    it("calls next with 404 when organization is not found", async () => {
      const User = { findById: () => ({ select: async () => makeUser() }) };
      const Organization = { findById: async () => null };
      const verifySession = () => ({ userId: "user-1" });
      const createError = (code, msg) => Object.assign(new Error(msg), { status: code });

      const controller = buildUpdateController({ User, Organization, verifySession, createError });

      let nextErr = null;
      await controller(
        makeReq({ body: { policyConfigurations: {} } }),
        makeRes(),
        (e) => { nextErr = e; }
      );

      assert.equal(nextErr.status, 404);
    });
  });
});

// ─── Controller factory helpers ───────────────────────────────────────────────
// Build controller functions with injected dependencies so we can unit-test
// without touching Mongoose or the session cookie infrastructure.

function buildGetController({ User, Organization, verifySession, createError }) {
  return async function getPolicyConfigurations(req, res, next) {
    try {
      const decoded = verifySession(req.cookies.authToken);
      const user = await User.findById(decoded.userId).select("organizationId role");

      if (!user) return next(createError(404, "User not found"));
      if (!user.organizationId) return next(createError(404, "User is not associated with any organization"));

      const organization = await Organization.findById(user.organizationId).select("policyConfigurations name");
      if (!organization) return next(createError(404, "Organization not found"));

      res.json({
        success: true,
        policyConfigurations: organization.policyConfigurations || {},
        userRole: user.role,
      });
    } catch (err) {
      next(err);
    }
  };
}

function buildUpdateController({ User, Organization, verifySession, createError }) {
  return async function updatePolicyConfigurations(req, res, next) {
    try {
      const decoded = verifySession(req.cookies.authToken);
      const user = await User.findById(decoded.userId).select("organizationId role");

      if (!user) return next(createError(404, "User not found"));
      if (!user.organizationId) return next(createError(404, "User is not associated with any organization"));

      const organization = await Organization.findById(user.organizationId);
      if (!organization) return next(createError(404, "Organization not found"));
      if (!organization.isAdmin(user._id)) return next(createError(403, "Only organization admin can update policy configurations"));

      const { policyConfigurations } = req.body;
      if (!policyConfigurations) return next(createError(400, "Policy configurations are required"));

      organization.policyConfigurations = policyConfigurations;
      organization.markModified("policyConfigurations");
      await organization.save();

      res.json({
        success: true,
        message: "Policy configurations updated successfully",
        policyConfigurations: organization.policyConfigurations,
      });
    } catch (err) {
      next(err);
    }
  };
}
