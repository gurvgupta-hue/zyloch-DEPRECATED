/**
 * Transactional email via Resend (https://resend.com/docs/api-reference/emails/send-email).
 *
 * Talks to Resend's HTTP API directly (no SDK dependency — `axios` is already
 * a project dependency and the API is a single POST).
 *
 * RESEND_API_KEY / RESEND_FROM_EMAIL are unset in every environment until an
 * operator fills them in via Vault (see .env.example). Until then this module
 * logs and no-ops rather than throwing, so member invites keep working with
 * email delivery simply disabled.
 */
const axios = require('axios');

const RESEND_API_URL = 'https://api.resend.com/emails';

function isConfigured() {
  return Boolean(process.env.RESEND_API_KEY && process.env.RESEND_FROM_EMAIL);
}

/**
 * Low-level send. Never throws — callers treat email as best-effort and must
 * not fail the request (e.g. an invite) just because delivery failed.
 * @returns {Promise<{ sent: boolean, error?: string }>}
 */
async function sendEmail({ to, subject, html, text }) {
  if (!isConfigured()) {
    console.warn(`[emailService] Skipping email to ${to}: RESEND_API_KEY/RESEND_FROM_EMAIL not configured`);
    return { sent: false, error: 'not_configured' };
  }

  try {
    await axios.post(
      RESEND_API_URL,
      {
        from: process.env.RESEND_FROM_EMAIL,
        to: [to],
        subject,
        html,
        text,
      },
      {
        headers: {
          Authorization: `Bearer ${process.env.RESEND_API_KEY}`,
          'Content-Type': 'application/json',
        },
        timeout: 10000,
      }
    );
    return { sent: true };
  } catch (err) {
    const detail = err.response?.data?.message || err.message;
    console.error(`[emailService] Failed to send email to ${to}: ${detail}`);
    return { sent: false, error: detail };
  }
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/**
 * Notifies a newly invited member that they've been added to an organization.
 * Fire-and-forget from the caller's perspective — resolves to a status object
 * instead of throwing so `inviteMember` can log/ignore failures without a
 * try/catch of its own.
 */
async function sendMemberAddedEmail({ to, orgName, adminName, inviteUrl }) {
  const safeOrg = escapeHtml(orgName || 'your organization');
  const safeAdmin = escapeHtml(adminName || 'an administrator');
  // Plain text (not HTML-escaped) — this goes in the email header, not the HTML body.
  const subject = `You've been added to ${orgName || 'your organization'} on Zyloch`;
  const signInUrl = inviteUrl || `${process.env.FRONTEND_URL || 'http://localhost:3000'}/login`;

  const html = `
  <!doctype html>
  <html>
    <body style="margin:0;padding:0;background:#f4f5f7;font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;">
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f4f5f7;padding:32px 0;">
        <tr>
          <td align="center">
            <table role="presentation" width="480" cellpadding="0" cellspacing="0" style="background:#ffffff;border-radius:12px;overflow:hidden;border:1px solid #e5e7eb;">
              <tr>
                <td style="background:#111827;padding:24px 32px;">
                  <span style="color:#ffffff;font-size:18px;font-weight:700;letter-spacing:0.2px;">Zyloch</span>
                </td>
              </tr>
              <tr>
                <td style="padding:32px;">
                  <h1 style="margin:0 0 16px;font-size:20px;color:#111827;">You've been added to an organization</h1>
                  <p style="margin:0 0 12px;font-size:14px;line-height:1.6;color:#374151;">
                    You have been added to <strong>${safeOrg}</strong> on Zyloch by admin
                    <strong>${safeAdmin}</strong>.
                  </p>
                  <p style="margin:0 0 24px;font-size:14px;line-height:1.6;color:#374151;">
                    Sign in with your work email to access the organization's dashboard.
                  </p>
                  <a href="${escapeHtml(signInUrl)}"
                     style="display:inline-block;background:#111827;color:#ffffff;text-decoration:none;font-size:14px;font-weight:600;padding:10px 20px;border-radius:8px;">
                    Sign in
                  </a>
                  <p style="margin:24px 0 0;font-size:12px;line-height:1.5;color:#9ca3af;">
                    If you weren't expecting this, you can safely ignore this email.
                  </p>
                </td>
              </tr>
            </table>
          </td>
        </tr>
      </table>
    </body>
  </html>`;

  const text = `You have been added to ${orgName || 'your organization'} on Zyloch by admin ${
    adminName || 'an administrator'
  }.\n\nSign in at ${signInUrl}`;

  return sendEmail({ to, subject, html, text });
}

module.exports = {
  isConfigured,
  sendEmail,
  sendMemberAddedEmail,
};
