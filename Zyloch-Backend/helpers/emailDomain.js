/**
 * Email-domain classification for tenant identity (MT-07.1).
 *
 * `organizations.domain` is a *claim*: it lets a colleague find their tenant by
 * typing their email domain on the login page. That only makes sense for a
 * domain one organization controls. A consumer mailbox domain does not identify
 * an organization — letting the first `@gmail.com` signup own "gmail.com" would
 * both be wrong and block every subsequent Gmail user from signing up at all.
 */

/**
 * Consumer / free mailbox providers. Not exhaustive by design — it only needs to
 * cover the domains real signups actually use, and an unlisted provider degrades
 * to "first signup claims it", which is the old behaviour minus the hard failure.
 */
const PUBLIC_EMAIL_DOMAINS = new Set([
  'gmail.com',
  'googlemail.com',
  'outlook.com',
  'hotmail.com',
  'live.com',
  'msn.com',
  'yahoo.com',
  'yahoo.co.uk',
  'yahoo.co.in',
  'ymail.com',
  'icloud.com',
  'me.com',
  'mac.com',
  'aol.com',
  'protonmail.com',
  'proton.me',
  'pm.me',
  'zoho.com',
  'gmx.com',
  'gmx.net',
  'mail.com',
  'yandex.com',
  'yandex.ru',
  'tutanota.com',
  'fastmail.com',
  'hey.com',
  'qq.com',
  '163.com',
  '126.com',
  // GitHub's no-reply address for users who hide their email.
  'users.noreply.github.com',
]);

/** Extract and normalize the domain part of an email address. */
function extractDomain(email) {
  const raw = String(email || '').trim().toLowerCase();
  const at = raw.lastIndexOf('@');
  if (at === -1 || at === raw.length - 1) return null;
  const domain = raw.slice(at + 1);
  return domain.includes('.') ? domain : null;
}

/** True when the domain is a consumer mailbox provider. */
function isPublicEmailDomain(domain) {
  const normalized = String(domain || '').trim().toLowerCase();
  if (!normalized) return false;
  if (PUBLIC_EMAIL_DOMAINS.has(normalized)) return true;
  // *.users.noreply.github.com and similar provider subdomains.
  return [...PUBLIC_EMAIL_DOMAINS].some((d) => normalized.endsWith(`.${d}`));
}

/**
 * The domain to record on a new organization, or null when the address cannot
 * identify one. Null domains are allowed and do not collide (partial index).
 */
function tenantDomainFromEmail(email) {
  const domain = extractDomain(email);
  if (!domain || isPublicEmailDomain(domain)) return null;
  return domain;
}

module.exports = {
  PUBLIC_EMAIL_DOMAINS,
  extractDomain,
  isPublicEmailDomain,
  tenantDomainFromEmail,
};
