const axios = require("axios");
const { signSession, buildSessionPayload, verifySession } = require("../utils/jwt");
const createError = require("../utils/createError");
const { setAuthCookie, clearAuthCookie } = require("../helpers/cookieHelper");
const { loginGithubAdmin } = require("../services/authRouting");
const { getControlModels } = require("../db/controlModels");
const { getTenantModels } = require("../db/tenantModels");

/** Step 1: Start OAuth — Redirect to GitHub */
async function startOAuth(req, res, next) {
  try {
    const params = new URLSearchParams({
      client_id: process.env.GITHUB_CLIENT_ID,
      redirect_uri: process.env.OAUTH_REDIRECT_URI,
      scope: "read:user user:email",
      prompt: "select_account",
    });
    res.redirect(`https://github.com/login/oauth/authorize?${params}`);
  } catch (err) {
    next(createError(500, "Failed to initiate OAuth flow"));
  }
}

/** Step 2: OAuth Callback — Handle GitHub Redirect */
async function oauthCallback(req, res, next) {
  try {
    const code = req.query.code;
    if (!code) return next(createError(400, "Missing code in OAuth callback"));

    const tokenRes = await axios.post(
      "https://github.com/login/oauth/access_token",
      {
        client_id: process.env.GITHUB_CLIENT_ID,
        client_secret: process.env.GITHUB_CLIENT_SECRET,
        code,
      },
      { headers: { Accept: "application/json" } }
    );

    const accessToken = tokenRes.data.access_token;
    if (!accessToken)
      return next(createError(500, "Failed to retrieve access token from GitHub"));

    const [userData, emailsData] = await Promise.all([
      axios.get("https://api.github.com/user", {
        headers: { Authorization: `Bearer ${accessToken}` },
      }),
      axios.get("https://api.github.com/user/emails", {
        headers: { Authorization: `Bearer ${accessToken}` },
      }),
    ]);

    const githubId = userData.data.id.toString();
    const login = userData.data.login;
    const accountType = userData.data.type || "User";
    // Only VERIFIED addresses (MT-07.1). An unverified address must never be
    // trusted here: the email domain decides which organization this login
    // claims, so accepting one would let anyone claim a tenant by typing its
    // domain into their GitHub account.
    const verifiedEmails = (emailsData.data || []).filter((e) => e.verified);
    const email =
      verifiedEmails.find((e) => e.primary)?.email || verifiedEmails[0]?.email || null;

    if (!email) {
      return next(
        createError(
          400,
          "GitHub account must have a verified email. Verify your address on GitHub and try again."
        )
      );
    }

    // NOTE (MT merge): main's domain -> SSO organization redirect is intentionally
    // NOT carried over here. Strategy C makes `organizations.domain` informational
    // only (see models/schemas/control/organizationSchema.js): tenancy is decided
    // by organization _id alone, and `oauthConfigurations` now lives in each
    // tenant's own `tenant_settings`, so a control-plane domain lookup cannot
    // reach it. Routing a GitHub login by email domain is the exact adoption
    // behaviour Strategy C removed.
    //
    // Resolve (or provision) the tenant for this GitHub admin.
    const { user, tenantId } = await loginGithubAdmin({
      providerId: githubId,
      providerData: {
        login,
        email,
        name: userData.data.name,
        avatar_url: userData.data.avatar_url,
        accountType,
      },
      tokens: { accessToken, refreshToken: null, tokenExpiry: null },
    });

    const sessionToken = signSession(
      buildSessionPayload({
        userId: user._id,
        tenantId,
        email: user.email,
        provider: "github",
        role: user.role,
      })
    );

    setAuthCookie(res, "authToken", sessionToken);
    res.redirect(`${process.env.FRONTEND_URL}/login/callback`);
  } catch (err) {
    next(err);
  }
}

/** Step 3: Logout — Clear Session Cookie */
async function logout(req, res, next) {
  try {
    clearAuthCookie(res, "authToken");
    // Best-effort session cleanup (from main #368), adapted to Strategy C:
    // the stored OAuth token lives on the user's identities in the TENANT DB,
    // and the tenant comes straight off the JWT rather than a User lookup.
    let decoded;

    const authToken = req.cookies?.authToken;
    if (authToken) {
      try {
        decoded = verifySession(authToken);
        if (decoded?.userId && decoded?.tenantId) {
          const { User } = getTenantModels(decoded.tenantId);
          await User.updateOne(
            { _id: decoded.userId },
            {
              $unset: {
                "identities.$[].accessToken": "",
                "identities.$[].refreshToken": "",
                "identities.$[].tokenExpiry": "",
              },
            }
          );
        }
      } catch (error) {
        console.warn("Logout session cleanup skipped:", error.message);
      }
    }

    const loginUrl = new URL("/login", process.env.FRONTEND_URL);
    // SSO members land back on their organization's login page; tenantId is the
    // canonical org id and is already in the session, so no DB read is needed.
    if (["google", "microsoft"].includes(decoded?.provider) && decoded?.tenantId) {
      loginUrl.searchParams.set("orgId", String(decoded.tenantId));
    }
    // Signals the frontend to serve Clear-Site-Data (HTTPS only) for this visit
    loginUrl.searchParams.set("loggedOut", "1");

    res.json({
      success: true,
      message: "Logged out successfully",
      redirectUrl: loginUrl.toString(),
    });
  } catch (err) {
    next(err);
  }
}

/** Step 4: Get Preferences */
async function getPreferences(req, res, next) {
  try {
    const user = await req.models.User.findById(req.user.id, "preferences");
    if (!user) return next(createError(404, "User not found"));
    res.json({ success: true, preferences: user.preferences });
  } catch (err) {
    next(err);
  }
}

/** Step 5: Update Preferences */
async function updatePreferences(req, res, next) {
  try {
    const { theme, timeZone } = req.body;
    const validThemes = ["light", "dark", "teal-modern", "teal-modern-dark"];
    const validTimeZones = ["UTC", "IST", "EST", "PST", "CET"];

    if (theme && !validThemes.includes(theme))
      return next(createError(400, "Invalid theme value"));
    if (timeZone && !validTimeZones.includes(timeZone))
      return next(createError(400, "Invalid timeZone value"));

    const user = await req.models.User.findByIdAndUpdate(
      req.user.id,
      { $set: { "preferences.theme": theme, "preferences.timeZone": timeZone } },
      { new: true, select: "preferences" }
    );

    res.json({ success: true, preferences: user.preferences });
  } catch (err) {
    next(err);
  }
}

/** Step 6: Get Current User */
async function getCurrentUser(req, res, next) {
  try {
    const user = await req.models.User.findById(req.user.id).select(
      "-identities.accessToken -identities.refreshToken"
    );
    if (!user) return next(createError(404, "User not found"));

    const { Organization } = getControlModels();
    const organization = await Organization.findById(req.tenantId)
      .select("name isActive")
      .lean();

    const userObj = user.toObject();
    userObj.tenantId = String(req.tenantId);
    userObj.organizationId = organization
      ? { _id: req.tenantId, name: organization.name, isActive: organization.isActive }
      : null;
    userObj.role = user.role;
    userObj.license = req.license
      ? {
          planId: req.license.planId,
          planName: req.license.plan?.name || null,
          status: req.license.status,
          active: req.license.active,
          entitlements: req.license.entitlements || {},
        }
      : null;

    res.json({ success: true, user: userObj });
  } catch (err) {
    next(err);
  }
}

/** Step 7: Check Auth — Validate JWT Session */
async function checkAuth(req, res, next) {
  try {
    const { verifySession } = require("../utils/jwt");
    const decoded = verifySession(req.cookies.authToken);
    res.json({ success: true, message: "Authenticated", user: decoded });
  } catch {
    res.status(401).json({ success: false, message: "Invalid or expired token" });
  }
}

/** Google OAuth Callback — req.user/req.tenantId set by dynamicOAuthHelper */
async function googleOAuthCallback(req, res, next) {
  try {
    const user = req.user;
    if (!user) return next(createError(401, "Authentication failed"));

    const sessionToken = signSession(
      buildSessionPayload({
        userId: user._id,
        tenantId: req.tenantId,
        email: user.email,
        provider: "google",
        role: user.role,
      })
    );

    setAuthCookie(res, "authToken", sessionToken);
    res.redirect(`${process.env.FRONTEND_URL}/login/callback`);
  } catch (err) {
    console.error("Google OAuth callback error:", err);
    next(err);
  }
}

/** Microsoft OAuth Callback — req.user/req.tenantId set by dynamicOAuthHelper */
async function microsoftOAuthCallback(req, res, next) {
  try {
    const user = req.user;
    if (!user) return next(createError(401, "Authentication failed"));

    const sessionToken = signSession(
      buildSessionPayload({
        userId: user._id,
        tenantId: req.tenantId,
        email: user.email,
        provider: "microsoft",
        role: user.role,
      })
    );

    setAuthCookie(res, "authToken", sessionToken);
    res.redirect(`${process.env.FRONTEND_URL}/login/callback`);
  } catch (err) {
    console.error("Microsoft OAuth callback error:", err);
    next(err);
  }
}

/** Get all linked identities for current user */
async function getLinkedIdentities(req, res, next) {
  try {
    const user = await req.models.User.findById(req.user.id).select(
      "identities primaryIdentity email name"
    );
    if (!user) return next(createError(404, "User not found"));

    const identities = user.identities.map((id) => ({
      provider: id.provider,
      email: id.providerData.email,
      name: id.providerData.name,
      lastUsedAt: id.lastUsedAt,
      createdAt: id.createdAt,
      isPrimary:
        id.provider === user.primaryIdentity.provider &&
        id.providerId === user.primaryIdentity.providerId,
    }));

    res.json({
      success: true,
      identities,
      primaryProvider: user.primaryIdentity.provider,
    });
  } catch (err) {
    next(err);
  }
}

/** Unlink an identity from user account */
async function unlinkIdentity(req, res, next) {
  try {
    const user = await req.models.User.findById(req.user.id);
    if (!user) return next(createError(404, "User not found"));

    const { provider } = req.body;
    if (!provider) return next(createError(400, "Provider is required"));

    await user.unlinkIdentity(provider);

    // Keep the control-plane routing table consistent.
    try {
      const { AuthIdentity } = getControlModels();
      await AuthIdentity.deleteOne({
        tenantId: req.tenantId,
        userId: user._id,
        provider,
      });
    } catch (e) {
      console.error("Failed to remove auth_identity routing on unlink:", e.message);
    }

    res.json({
      success: true,
      message: `${provider} identity unlinked successfully`,
      linkedProviders: user.getLinkedProviders(),
    });
  } catch (err) {
    if (err.message.includes("Cannot unlink")) {
      return next(createError(400, err.message));
    }
    next(err);
  }
}

/** List orgs for the current session identity (KAN-49). */
async function listMyOrganizations(req, res, next) {
  try {
    const { listTenantsForIdentity } = require('../services/authRouting');
    const provider = req.user.provider;
    const providerId =
      provider === 'github'
        ? req.user.githubId
        : req.user.identities?.find?.((i) => i.provider === provider)?.providerId;

    // Load full user for identity providerId
    const user = await req.models.User.findById(req.user.id).select('identities primaryIdentity');
    const identity =
      user?.getIdentity?.(provider) ||
      user?.identities?.find((i) => i.provider === provider);
    const pid = identity?.providerId || providerId;
    if (!provider || !pid) {
      return res.json({
        success: true,
        organizations: [
          {
            tenantId: String(req.tenantId),
            name: null,
            domain: null,
            current: true,
          },
        ],
      });
    }

    const orgs = await listTenantsForIdentity(provider, pid);
    res.json({
      success: true,
      organizations: orgs.map((o) => ({
        ...o,
        current: String(o.tenantId) === String(req.tenantId),
      })),
    });
  } catch (err) {
    next(err);
  }
}

/**
 * Re-issue JWT for another tenant the identity already belongs to (KAN-49).
 * Requires re-auth design: same cookie session is replaced — no silent cross-tenant flash.
 */
async function switchOrganization(req, res, next) {
  try {
    const targetTenantId = req.body?.tenantId || req.body?.orgId;
    if (!targetTenantId) return next(createError(400, 'tenantId is required'));

    const { switchTenantForIdentity } = require('../services/authRouting');
    const user = await req.models.User.findById(req.user.id).select('identities primaryIdentity');
    const provider = req.user.provider || user?.primaryIdentity?.provider;
    const identity = user?.getIdentity?.(provider);
    if (!provider || !identity?.providerId) {
      return next(createError(400, 'No OAuth identity available to switch organizations'));
    }

    const { user: targetUser, tenantId } = await switchTenantForIdentity({
      provider,
      providerId: identity.providerId,
      targetTenantId,
    });

    const sessionToken = signSession(
      buildSessionPayload({
        userId: targetUser._id,
        tenantId,
        email: targetUser.email,
        provider,
        role: targetUser.role,
      })
    );
    setAuthCookie(res, 'authToken', sessionToken);

    res.json({
      success: true,
      message: 'Switched organization. Session re-issued.',
      tenantId: String(tenantId),
      role: targetUser.role,
    });
  } catch (err) {
    if (err.statusCode) return next(createError(err.statusCode, err.message));
    next(err);
  }
}

module.exports = {
  startOAuth,
  oauthCallback,
  logout,
  getPreferences,
  updatePreferences,
  getCurrentUser,
  checkAuth,
  googleOAuthCallback,
  microsoftOAuthCallback,
  getLinkedIdentities,
  unlinkIdentity,
  listMyOrganizations,
  switchOrganization,
};
