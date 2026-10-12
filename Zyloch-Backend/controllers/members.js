const crypto = require('crypto');
const createError = require('../utils/createError');
const { assertUserCapacity, countTenantUsers, syncUsageMetrics } = require('../services/licenseLimits');
const { presentLimit } = require('../services/licenseEntitlements');
const { sendMemberAddedEmail } = require('../services/emailService');

const INVITE_TTL_MS = 7 * 24 * 60 * 60 * 1000;

function publicMember(user) {
  return {
    id: String(user._id),
    email: user.email,
    name: user.name || null,
    avatar_url: user.avatar_url || null,
    role: user.role,
    isActive: user.isActive !== false,
    lastLoginAt: user.lastLoginAt || null,
    createdAt: user.createdAt || null,
  };
}

function publicInvite(invite) {
  return {
    id: String(invite._id),
    email: invite.email,
    invitedAt: invite.createdAt || null,
    expiresAt: invite.expiresAt || null,
  };
}

/** GET /api/organization/members — list tenant users + pending invites (scoped by req.tenantId). */
async function listMembers(req, res, next) {
  try {
    const { MemberInvite } = req.models;

    const [users, pendingInvites, activeCount, maxUsers] = await Promise.all([
      req.models.User.find({})
        .select('email name avatar_url role isActive lastLoginAt createdAt')
        .sort({ role: 1, createdAt: 1 })
        .lean(),
      MemberInvite.find({
        tenantId: req.tenantId,
        status: 'pending',
        expiresAt: { $gt: new Date() },
      })
        .select('email createdAt expiresAt')
        .sort({ createdAt: -1 })
        .lean(),
      countTenantUsers(req.tenantId, { activeOnly: true }),
      // null == unlimited: per-seat plans have no ceiling, seats are billed.
      Promise.resolve(presentLimit(req.license?.entitlements?.maxUsers)),
    ]);

    res.json({
      success: true,
      members: users.map(publicMember),
      pendingInvites: pendingInvites.map(publicInvite),
      usage: {
        users: { current: activeCount, max: maxUsers },
      },
    });
  } catch (err) {
    next(err);
  }
}

/** POST /api/organization/members/invite — admin invite by email. */
async function inviteMember(req, res, next) {
  try {
    const email = String(req.body?.email || '')
      .trim()
      .toLowerCase();
    if (!email || !email.includes('@')) {
      return next(createError(400, 'A valid email is required'));
    }

    const existingUser = await req.models.User.findOne({ email }).lean();
    if (existingUser) {
      return next(createError(409, 'A user with this email already belongs to the organization'));
    }

    const { MemberInvite } = req.models;
    const pending = await MemberInvite.findOne({
      tenantId: req.tenantId,
      email,
      status: 'pending',
      expiresAt: { $gt: new Date() },
    }).lean();
    if (pending) {
      return next(createError(409, 'An active invite already exists for this email'));
    }

    try {
      await assertUserCapacity(req.tenantId, {
        entitlements: req.license?.entitlements,
        active: req.license?.active,
      });
    } catch (limitErr) {
      if (limitErr.code === 'LICENSE_LIMIT_EXCEEDED') {
        return next(
          createError(
            403,
            `Cannot invite: user seat limit reached (${limitErr.current}/${limitErr.limit}). Upgrade the plan or deactivate unused members.`
          )
        );
      }
      throw limitErr;
    }

    const token = crypto.randomBytes(24).toString('hex');
    const invite = await MemberInvite.create({
      tenantId: req.tenantId,
      email,
      invitedBy: req.user.id,
      status: 'pending',
      token,
      expiresAt: new Date(Date.now() + INVITE_TTL_MS),
    });

    // Email delivery is optional; return invite link for admin to share.
    const frontend = process.env.FRONTEND_URL || 'http://localhost:3000';
    // `org_id` is how a member reaches the SSO buttons: the login page shows
    // Google/Microsoft only when it knows which organization to sign in to, and
    // there is no way to look that up (by design — see publicDiscoveryLimiter).
    const inviteUrl = `${frontend}/login?org_id=${req.tenantId}&invite=${invite.token}&email=${encodeURIComponent(email)}`;

    // Best-effort notification — a failed send must not fail the invite itself
    // (the admin still has the invite link to share by hand).
    sendMemberAddedEmail({
      to: email,
      orgName: req.organization?.name,
      adminName: req.user?.name || req.user?.login || req.user?.email,
      inviteUrl,
    }).catch((err) => console.error('[inviteMember] Email notification failed:', err.message));

    res.status(201).json({
      success: true,
      message: 'Invite created. Share the login link with the member (Google/Microsoft with this org).',
      invite: {
        id: String(invite._id),
        email: invite.email,
        status: invite.status,
        expiresAt: invite.expiresAt,
        inviteUrl,
      },
    });
  } catch (err) {
    next(err);
  }
}

/** POST /api/organization/members/:userId/deactivate — admin only. */
async function deactivateMember(req, res, next) {
  try {
    const { userId } = req.params;
    if (!userId) return next(createError(400, 'userId is required'));

    if (String(userId) === String(req.user.id)) {
      return next(createError(400, 'You cannot deactivate your own account'));
    }

    const user = await req.models.User.findById(userId);
    if (!user) return next(createError(404, 'Member not found'));

    if (user.role === 'admin') {
      return next(createError(403, 'Cannot deactivate an organization admin'));
    }

    user.isActive = false;
    await user.save();
    await syncUsageMetrics(req.tenantId).catch(() => {});

    res.json({
      success: true,
      message: 'Member deactivated',
      member: publicMember(user),
    });
  } catch (err) {
    next(err);
  }
}

/** POST /api/organization/members/:userId/reactivate — admin only. */
async function reactivateMember(req, res, next) {
  try {
    const { userId } = req.params;
    const user = await req.models.User.findById(userId);
    if (!user) return next(createError(404, 'Member not found'));

    if (user.isActive !== false) {
      return res.json({ success: true, message: 'Member already active', member: publicMember(user) });
    }

    try {
      await assertUserCapacity(req.tenantId, {
        entitlements: req.license?.entitlements,
        active: req.license?.active,
      });
    } catch (limitErr) {
      if (limitErr.code === 'LICENSE_LIMIT_EXCEEDED') {
        return next(
          createError(
            403,
            `Cannot reactivate: user seat limit reached (${limitErr.current}/${limitErr.limit}).`
          )
        );
      }
      throw limitErr;
    }

    user.isActive = true;
    await user.save();
    await syncUsageMetrics(req.tenantId).catch(() => {});

    res.json({ success: true, message: 'Member reactivated', member: publicMember(user) });
  } catch (err) {
    next(err);
  }
}

/** DELETE /api/organization/members/:userId — admin only. Permanently removes the member. */
async function deleteMember(req, res, next) {
  try {
    const { userId } = req.params;
    if (!userId) return next(createError(400, 'userId is required'));

    if (String(userId) === String(req.user.id)) {
      return next(createError(400, 'You cannot delete your own account'));
    }

    const user = await req.models.User.findById(userId);
    if (!user) return next(createError(404, 'Member not found'));

    if (user.role === 'admin') {
      return next(createError(403, 'Cannot delete an organization admin'));
    }

    const removed = publicMember(user);
    await user.deleteOne();
    await syncUsageMetrics(req.tenantId).catch(() => {});

    res.json({
      success: true,
      message: 'Member deleted',
      member: removed,
    });
  } catch (err) {
    next(err);
  }
}

/** POST /api/organization/members/invites/:inviteId/revoke — admin only. */
async function revokeInvite(req, res, next) {
  try {
    const { inviteId } = req.params;
    if (!inviteId) return next(createError(400, 'inviteId is required'));

    const { MemberInvite } = req.models;
    const invite = await MemberInvite.findOne({ _id: inviteId, tenantId: req.tenantId });
    if (!invite) return next(createError(404, 'Invite not found'));

    if (invite.status !== 'pending') {
      return res.json({
        success: true,
        message: `Invite already ${invite.status}`,
        invite: publicInvite(invite),
      });
    }

    invite.status = 'revoked';
    await invite.save();

    res.json({ success: true, message: 'Invite revoked', invite: publicInvite(invite) });
  } catch (err) {
    next(err);
  }
}

module.exports = {
  listMembers,
  inviteMember,
  deactivateMember,
  reactivateMember,
  deleteMember,
  revokeInvite,
};
