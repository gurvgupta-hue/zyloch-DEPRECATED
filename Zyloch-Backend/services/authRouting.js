/**
 * Authentication routing across the control plane and tenant databases.
 *
 * Login flow (Strategy C):
 *   - GitHub login => the user is an admin who owns a tenant. The first GitHub
 *     login provisions a brand new tenant DB; subsequent logins resolve the
 *     tenant via the control-plane `auth_identities` table.
 *   - Google / Microsoft login => the user is a member of an existing tenant and
 *     MUST carry the tenantId (orgId). We resolve/validate the tenant, then load
 *     or create the member user inside that tenant DB.
 */

const mongoose = require('mongoose');
const { getControlModels } = require('../db/controlModels');
const { getTenantModels } = require('../db/tenantModels');
const { provisionTenant } = require('./tenantProvisioning');
const { assertUserCapacity, syncUsageMetrics } = require('./licenseLimits');
const { tenantDomainFromEmail } = require('../helpers/emailDomain');

/**
 * Failure codes for the member login path (MT-02). Surfaced to the login page as
 * `?error=<code>` so an uninvited visitor gets a real explanation instead of a
 * generic "auth failed".
 */
const MEMBER_LOGIN_ERRORS = Object.freeze({
  ORG_NOT_FOUND: 'org_not_found',
  ORG_INACTIVE: 'org_inactive',
  ACCOUNT_DEACTIVATED: 'account_deactivated',
  INVITE_REQUIRED: 'invite_required',
});

function memberLoginError(message, code, statusCode = 403) {
  return Object.assign(new Error(message), { code, statusCode });
}

function applyIdentity(user, { provider, providerId, providerData, tokens }) {
  const pid = String(providerId);
  const idx = user.identities.findIndex(
    (i) => i.provider === provider && i.providerId === pid
  );
  if (idx >= 0) {
    user.identities[idx].providerData = providerData;
    user.identities[idx].accessToken = tokens.accessToken;
    user.identities[idx].refreshToken = tokens.refreshToken;
    user.identities[idx].tokenExpiry = tokens.tokenExpiry;
    user.identities[idx].lastUsedAt = new Date();
  } else {
    user.identities.push({
      provider,
      providerId: pid,
      providerData,
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
      tokenExpiry: tokens.tokenExpiry,
      lastUsedAt: new Date(),
    });
  }
  user.primaryIdentity = { provider, providerId: pid };
  user.lastLoginAt = new Date();
  if (providerData.name) user.name = providerData.name;
  if (providerData.avatar_url) user.avatar_url = providerData.avatar_url;
}

/** Resolve which tenant owns a given external identity. */
async function resolveTenantByIdentity(provider, providerId) {
  const { AuthIdentity } = getControlModels();
  const record = await AuthIdentity.findOne({ provider, providerId: String(providerId) }).lean();
  if (!record) return null;
  return { tenantId: record.tenantId, userId: record.userId };
}

/** Resolve which tenant owns a given GitHub installation id. */
async function getTenantByInstallationId(githubInstallationId) {
  const { InstallationIndex } = getControlModels();
  const record = await InstallationIndex.findOne({
    githubInstallationId: Number(githubInstallationId),
  }).lean();
  return record ? record.tenantId : null;
}

/**
 * GitHub login: admin who owns a tenant. Provisions a new tenant on first login.
 * @returns {Promise<{ user, tenantId }>}
 */
async function loginGithubAdmin({ providerId, providerData, tokens }) {
  const email = providerData.email;
  if (!email) throw new Error('Email is required from GitHub');

  const { AuthIdentity } = getControlModels();
  const existing = await AuthIdentity.findOne({ provider: 'github', providerId: String(providerId) });

  if (existing) {
    const tenantId = existing.tenantId;
    const { User } = getTenantModels(tenantId);
    const user = await User.findById(existing.userId);
    if (user) {
      applyIdentity(user, { provider: 'github', providerId, providerData, tokens });
      if (providerData.accountType) user.accountType = providerData.accountType;
      await user.save();
      return { user, tenantId };
    }
    // Stale index → fall through to recreate the user in its tenant.
    const recreated = await User.create({
      _id: existing.userId,
      email,
      name: providerData.name,
      avatar_url: providerData.avatar_url,
      login: providerData.login || email.split('@')[0],
      githubId: Number(providerId),
      accountType: providerData.accountType || 'User',
      role: 'admin',
      identities: [
        {
          provider: 'github',
          providerId: String(providerId),
          providerData,
          accessToken: tokens.accessToken,
          refreshToken: tokens.refreshToken,
          tokenExpiry: tokens.tokenExpiry,
          lastUsedAt: new Date(),
        },
      ],
      primaryIdentity: { provider: 'github', providerId: String(providerId) },
    });
    return { user: recreated, tenantId };
  }

  // First-ever login for this GitHub identity.
  //
  // Always a brand new organization with its own id. A GitHub sign-in never joins
  // an existing tenant: two colleagues at one company who each sign up get two
  // independent organizations, which is the intended product behaviour. Joining
  // someone else's tenant is exclusively the invite path (see loginMember).
  const userId = new mongoose.Types.ObjectId();
  const normalizedEmail = String(email).trim().toLowerCase();

  const { tenantId } = await provisionTenant({
    name: `${providerData.name || providerData.login || normalizedEmail.split('@')[0]}'s Organization`,
    // Informational label only — nothing keys off it, and consumer mailbox
    // domains are recorded as null rather than pretending to name a company.
    domain: tenantDomainFromEmail(normalizedEmail),
    adminUserId: userId,
  });

  const { User } = getTenantModels(tenantId);
  const user = await User.create({
    _id: userId,
    email: normalizedEmail,
    name: providerData.name,
    avatar_url: providerData.avatar_url,
    login: providerData.login || normalizedEmail.split('@')[0],
    githubId: Number(providerId),
    accountType: providerData.accountType || 'User',
    role: 'admin',
    identities: [
      {
        provider: 'github',
        providerId: String(providerId),
        providerData,
        accessToken: tokens.accessToken,
        refreshToken: tokens.refreshToken,
        tokenExpiry: tokens.tokenExpiry,
        lastUsedAt: new Date(),
      },
    ],
    primaryIdentity: { provider: 'github', providerId: String(providerId) },
  });

  await AuthIdentity.create({
    provider: 'github',
    providerId: String(providerId),
    tenantId,
    userId,
    email: normalizedEmail,
  });

  return { user, tenantId };
}

/**
 * Google / Microsoft login: member of an existing tenant. Requires tenantId.
 *
 * Three distinct outcomes (MT-02.1):
 *   1. Known identity        → returning member, sign in.
 *   2. Known email, new IdP  → same person adding a provider, attach the identity.
 *   3. Unknown person        → JOIN. Requires a pending, unexpired invite issued
 *      to this exact email by a tenant admin.
 *
 * Case 3 is the gate. Without it, holding a tenantId — which is discoverable —
 * was enough for any Google/Microsoft account to enrol itself into the tenant.
 *
 * @returns {Promise<{ user, tenantId }>}
 */
async function loginMember({ provider, providerId, providerData, tokens, tenantId }) {
  if (!tenantId) throw new Error(`${provider} authentication requires an organization ID`);
  const email = providerData.email;
  if (!email) throw new Error(`Email is required from ${provider}`);
  const normalizedEmail = String(email).trim().toLowerCase();

  const { Organization, AuthIdentity } = getControlModels();
  const org = await Organization.findById(tenantId);
  if (!org) {
    throw memberLoginError('Organization not found', MEMBER_LOGIN_ERRORS.ORG_NOT_FOUND, 404);
  }
  if (!org.isActive) {
    throw memberLoginError('Organization is not active', MEMBER_LOGIN_ERRORS.ORG_INACTIVE);
  }

  const { User, MemberInvite } = getTenantModels(tenantId);

  // --- 1. Returning member: this exact identity is already mapped to the tenant.
  const existing = await AuthIdentity.findOne({
    provider,
    providerId: String(providerId),
    tenantId,
  });
  if (existing) {
    const user = await User.findById(existing.userId);
    if (user) {
      if (user.isActive === false) {
        throw memberLoginError(
          'Your account has been deactivated for this organization',
          MEMBER_LOGIN_ERRORS.ACCOUNT_DEACTIVATED
        );
      }
      applyIdentity(user, { provider, providerId, providerData, tokens });
      await user.save();
      return { user, tenantId: org._id };
    }
    // Stale index → fall through and re-resolve by email.
  }

  // --- 2. Existing member signing in with a different provider for the first time.
  // Already a member, so no invite is required; attach rather than duplicate the user.
  const existingUser = await User.findOne({ email: normalizedEmail });
  if (existingUser) {
    if (existingUser.isActive === false) {
      throw memberLoginError(
        'Your account has been deactivated for this organization',
        MEMBER_LOGIN_ERRORS.ACCOUNT_DEACTIVATED
      );
    }
    applyIdentity(existingUser, { provider, providerId, providerData, tokens });
    await existingUser.save();

    await AuthIdentity.updateOne(
      { provider, providerId: String(providerId), tenantId: org._id },
      {
        $setOnInsert: {
          provider,
          providerId: String(providerId),
          tenantId: org._id,
          userId: existingUser._id,
          email: normalizedEmail,
        },
      },
      { upsert: true }
    );

    return { user: existingUser, tenantId: org._id };
  }

  // --- 3. Join request: an admin must have invited this email.
  // Same identity may exist on another tenant (KAN-49 multi-org) — that is allowed,
  // but it grants no standing here; every tenant is joined on its own invite.
  const invite = await MemberInvite.findOne({
    tenantId: org._id,
    email: normalizedEmail,
    status: 'pending',
    expiresAt: { $gt: new Date() },
  });

  if (!invite) {
    throw memberLoginError(
      'You do not have an active invitation to this organization. Ask an administrator to invite you.',
      MEMBER_LOGIN_ERRORS.INVITE_REQUIRED
    );
  }

  await assertUserCapacity(tenantId);

  const userId = new mongoose.Types.ObjectId();
  const user = await User.create({
    _id: userId,
    email: normalizedEmail,
    name: providerData.name,
    avatar_url: providerData.avatar_url,
    login: providerData.login || normalizedEmail.split('@')[0],
    accountType: 'User',
    role: 'member',
    identities: [
      {
        provider,
        providerId: String(providerId),
        providerData,
        accessToken: tokens.accessToken,
        refreshToken: tokens.refreshToken,
        tokenExpiry: tokens.tokenExpiry,
        lastUsedAt: new Date(),
      },
    ],
    primaryIdentity: { provider, providerId: String(providerId) },
  });

  await AuthIdentity.create({
    provider,
    providerId: String(providerId),
    tenantId: org._id,
    userId,
    email: normalizedEmail,
  });

  // Redeem the invite so the link is single-use.
  await MemberInvite.updateOne(
    { _id: invite._id, status: 'pending' },
    { $set: { status: 'accepted', acceptedAt: new Date(), acceptedUserId: userId } }
  );

  await syncUsageMetrics(tenantId);

  return { user, tenantId: org._id };
}

/**
 * List organizations the current OAuth identity can access (KAN-49).
 */
async function listTenantsForIdentity(provider, providerId) {
  const { AuthIdentity, Organization } = getControlModels();
  const rows = await AuthIdentity.find({
    provider,
    providerId: String(providerId),
  }).lean();

  const out = [];
  for (const row of rows) {
    const org = await Organization.findById(row.tenantId).select('name domain isActive').lean();
    if (!org || !org.isActive) continue;
    out.push({
      tenantId: String(row.tenantId),
      name: org.name,
      domain: org.domain,
      userId: String(row.userId),
    });
  }
  return out;
}

/**
 * Switch session to another tenant the identity already belongs to.
 * Returns { user, tenantId } for JWT re-issue.
 */
async function switchTenantForIdentity({ provider, providerId, targetTenantId }) {
  const { AuthIdentity, Organization } = getControlModels();
  const org = await Organization.findById(targetTenantId);
  if (!org || !org.isActive) {
    throw Object.assign(new Error('Organization not found or inactive'), { statusCode: 404 });
  }

  const identity = await AuthIdentity.findOne({
    provider,
    providerId: String(providerId),
    tenantId: targetTenantId,
  });
  if (!identity) {
    throw Object.assign(new Error('You do not have access to this organization'), { statusCode: 403 });
  }

  const { User } = getTenantModels(targetTenantId);
  const user = await User.findById(identity.userId);
  if (!user) {
    throw Object.assign(new Error('User not found in target organization'), { statusCode: 404 });
  }
  if (user.isActive === false) {
    throw Object.assign(new Error('Your account has been deactivated for this organization'), {
      statusCode: 403,
    });
  }

  return { user, tenantId: org._id };
}

module.exports = {
  MEMBER_LOGIN_ERRORS,
  resolveTenantByIdentity,
  getTenantByInstallationId,
  loginGithubAdmin,
  loginMember,
  applyIdentity,
  listTenantsForIdentity,
  switchTenantForIdentity,
};
