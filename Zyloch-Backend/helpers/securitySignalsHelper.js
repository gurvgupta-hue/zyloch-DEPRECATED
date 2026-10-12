const axios = require('axios');

// Strategy C: the GitHubSecurityEvent model is tenant-scoped and passed in by
// the caller (resolved from the tenant connection) rather than imported globally.

const OVER_PERMISSIVE_PAT_THRESHOLD = 5;
const SECURITY_SIGNALS_DEBUG =
  process.env.SECURITY_SIGNALS_DEBUG === 'true' ||
  process.env.NODE_ENV === 'development';

function debugLog(message, data = null) {
  if (!SECURITY_SIGNALS_DEBUG) return;
  if (data !== null && data !== undefined) {
    console.log(`[SecuritySignals] ${message}`, data);
    return;
  }
  console.log(`[SecuritySignals] ${message}`);
}

function toDate(value, fallback = new Date()) {
  if (!value) return fallback;
  if (value instanceof Date && !Number.isNaN(value.getTime())) return value;
  if (typeof value === 'number') {
    const dt = new Date(value > 9999999999 ? value : value * 1000);
    if (!Number.isNaN(dt.getTime())) return dt;
  }
  const dt = new Date(value);
  return Number.isNaN(dt.getTime()) ? fallback : dt;
}

function sanitizeString(value) {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  return trimmed.length ? trimmed : null;
}

function parsePatPermissions(permissions) {
  if (!permissions) return { normalized: {}, writeLikeCount: 0 };

  if (typeof permissions === 'string') {
    const normalized = {};
    const scopes = permissions
      .split(',')
      .map((scope) => scope.trim())
      .filter(Boolean);

    let writeLikeCount = 0;
    scopes.forEach((scope) => {
      normalized[scope] = 'granted';
      if (scope.includes('write') || scope.includes('admin') || scope === 'repo' || scope === 'workflow') {
        writeLikeCount += 1;
      }
    });

    return { normalized, writeLikeCount };
  }

  if (Array.isArray(permissions)) {
    const normalized = {};
    permissions.forEach((permission) => {
      if (typeof permission === 'string') {
        normalized[permission] = 'granted';
      }
    });
    return { normalized, writeLikeCount: 0 };
  }

  if (typeof permissions === 'object') {
    const normalized = {};
    let writeLikeCount = 0;

    for (const [key, value] of Object.entries(permissions)) {
      const normalizedValue = typeof value === 'string' ? value.toLowerCase() : String(value).toLowerCase();
      normalized[key] = normalizedValue;
      if (normalizedValue === 'write' || normalizedValue === 'admin') {
        writeLikeCount += 1;
      }
    }

    return { normalized, writeLikeCount };
  }

  return { normalized: {}, writeLikeCount: 0 };
}

function buildDedupeKey(prefix, installationId, accountId, uniqueParts = []) {
  const safeParts = uniqueParts
    .map((part) => (part === undefined || part === null ? 'na' : String(part).trim() || 'na'))
    .join('|');

  return `${prefix}|${installationId}|${accountId}|${safeParts}`;
}

async function upsertSecurityEvent(SecurityEvent, payload) {
  if (!payload?.dedupeKey) {
    throw new Error('dedupeKey is required for security event upsert');
  }

  await SecurityEvent.findOneAndUpdate(
    { dedupeKey: payload.dedupeKey },
    payload,
    { upsert: true, new: true, setDefaultsOnInsert: true }
  );
}

function getPatRequestObject(body) {
  return body?.personal_access_token_request || {};
}

function buildPatBaseEvent({ body, signalType, action, severity, dedupeSuffix, deliveryId, metadata = {}, tenantId }) {
  const installationId = body?.installation?.id;
  const org = body?.organization || {};
  const accountId = org?.id || body?.installation?.account?.id;
  const login = org?.login || body?.installation?.account?.login;
  const patRequest = getPatRequestObject(body);
  const expiresAt = toDate(patRequest?.expires_at || patRequest?.token_expires_at, null);
  const { normalized: parsedPermissions, writeLikeCount } = parsePatPermissions(
    patRequest?.permissions || patRequest?.permission || patRequest?.scopes
  );

  const tokenId = sanitizeString(patRequest?.token_id || patRequest?.id);
  const requestId = sanitizeString(patRequest?.request_id || patRequest?.id || patRequest?.node_id);

  const occurredAt = toDate(body?.sender?.updated_at || body?.updated_at || body?.created_at || new Date());
  const hasNoExpiry = !expiresAt;
  const isExpired = !!expiresAt && expiresAt < new Date();
  const isOverPermissive = writeLikeCount >= OVER_PERMISSIVE_PAT_THRESHOLD;

  return {
    tenantId,
    installationId,
    accountId,
    login,
    source: 'webhook',
    signalType,
    severity,
    action,
    status: 'active',
    occurredAt,
    actor: {
      id: sanitizeString(body?.sender?.id),
      login: sanitizeString(body?.sender?.login),
    },
    organization: {
      id: org?.id || null,
      login: sanitizeString(org?.login),
    },
    pat: {
      requestId,
      tokenId,
      expiresAt,
      permissions: parsedPermissions,
      hasNoExpiry,
      isExpired,
      isOverPermissive,
    },
    metadata: {
      ...metadata,
      writeLikePermissionCount: writeLikeCount,
    },
    rawPayload: body,
    dedupeKey: buildDedupeKey(
      'webhook-pat',
      installationId,
      accountId,
      [deliveryId || 'no-delivery-id', signalType, dedupeSuffix || requestId || tokenId || occurredAt.toISOString()]
    ),
  };
}

async function ingestPatRequestWebhook(SecurityEvent, body, deliveryId, tenantId) {
  const action = sanitizeString(body?.action) || 'unknown';
  const installationId = body?.installation?.id;
  const org = body?.organization || {};
  const accountId = org?.id || body?.installation?.account?.id;
  const login = org?.login || body?.installation?.account?.login;

  if (!tenantId || !installationId || !accountId || !login) {
    return { inserted: 0, installationId: null, accountId: null, login: null };
  }

  const entries = [];

  if (action === 'created') {
    entries.push(buildPatBaseEvent({
      body,
      signalType: 'pat_request_created',
      action,
      severity: 'low',
      dedupeSuffix: 'lifecycle-created',
      deliveryId,
      tenantId,
    }));
  } else if (action === 'approved') {
    entries.push(buildPatBaseEvent({
      body,
      signalType: 'pat_request_approved',
      action,
      severity: 'low',
      dedupeSuffix: 'lifecycle-approved',
      deliveryId,
      tenantId,
    }));
  } else if (action === 'denied' || action === 'cancelled') {
    entries.push(buildPatBaseEvent({
      body,
      signalType: 'pat_request_denied',
      action,
      severity: 'low',
      dedupeSuffix: `lifecycle-${action}`,
      deliveryId,
      tenantId,
    }));
  }

  const riskProbe = buildPatBaseEvent({
    body,
    signalType: 'pat_no_expiry',
    action,
    severity: 'high',
    dedupeSuffix: 'risk-probe',
    deliveryId,
    tenantId,
  });

  if (riskProbe?.pat?.hasNoExpiry) {
    entries.push({
      ...riskProbe,
      signalType: 'pat_no_expiry',
      severity: 'high',
      dedupeKey: buildDedupeKey('webhook-pat', installationId, accountId, [deliveryId || 'no-delivery-id', 'pat_no_expiry']),
    });
  }

  if (riskProbe?.pat?.isExpired) {
    entries.push({
      ...riskProbe,
      signalType: 'pat_expired',
      severity: 'medium',
      dedupeKey: buildDedupeKey('webhook-pat', installationId, accountId, [deliveryId || 'no-delivery-id', 'pat_expired']),
    });
  }

  if (riskProbe?.pat?.isOverPermissive) {
    entries.push({
      ...riskProbe,
      signalType: 'pat_over_permissive',
      severity: 'high',
      dedupeKey: buildDedupeKey('webhook-pat', installationId, accountId, [deliveryId || 'no-delivery-id', 'pat_over_permissive']),
    });
  }

  for (const entry of entries) {
    await upsertSecurityEvent(SecurityEvent, entry);
  }

  return { inserted: entries.length, installationId, accountId, login };
}

async function ingestForkWebhook(SecurityEvent, body, deliveryId, tenantId) {
  const installationId = body?.installation?.id;
  const repository = body?.repository || {};
  const forkee = body?.forkee || {};
  const sourceOwner = sanitizeString(repository?.owner?.login);
  const forkeeOwner = sanitizeString(forkee?.owner?.login);

  const org = body?.organization || {};
  const accountId = org?.id || body?.installation?.account?.id || repository?.owner?.id;
  const login = sanitizeString(org?.login) || sanitizeString(repository?.owner?.login) || sanitizeString(body?.installation?.account?.login);

  if (!tenantId || !installationId || !accountId || !login || !sourceOwner || !forkeeOwner) {
    return { inserted: 0, installationId: null, accountId: null, login: null };
  }

  const isExternal = sourceOwner.toLowerCase() !== forkeeOwner.toLowerCase();
  if (!isExternal) {
    return { inserted: 0, installationId, accountId, login };
  }

  const occurredAt = toDate(body?.forkee?.created_at || body?.repository?.updated_at || new Date());

  await upsertSecurityEvent(SecurityEvent, {
    tenantId,
    installationId,
    accountId,
    login,
    source: 'webhook',
    signalType: 'external_org_fork',
    severity: 'medium',
    action: 'fork',
    status: 'active',
    occurredAt,
    actor: {
      id: sanitizeString(body?.sender?.id),
      login: sanitizeString(body?.sender?.login),
    },
    organization: {
      id: org?.id || null,
      login: sanitizeString(org?.login),
    },
    repository: {
      id: repository?.id || null,
      name: sanitizeString(repository?.name),
      fullName: sanitizeString(repository?.full_name),
      url: sanitizeString(repository?.html_url),
      ownerLogin: sourceOwner,
      visibility: sanitizeString(repository?.visibility),
      isPrivate: typeof repository?.private === 'boolean' ? repository.private : null,
    },
    metadata: {
      sourceRepository: sanitizeString(repository?.full_name),
      forkeeRepository: sanitizeString(forkee?.full_name),
      sourceOwner,
      forkeeOwner,
    },
    rawPayload: body,
    dedupeKey: buildDedupeKey('webhook-fork', installationId, accountId, [
      deliveryId || 'no-delivery-id',
      sanitizeString(repository?.full_name),
      sanitizeString(forkee?.full_name),
      occurredAt.toISOString(),
    ]),
  });

  return { inserted: 1, installationId, accountId, login };
}

function mapAuditActionToSignalType(action) {
  const normalized = (action || '').toLowerCase();

  if (normalized === 'org_credential_authorization.grant') {
    return 'pat_request_approved';
  }

  if (
    normalized === 'org_credential_authorization.revoke' ||
    normalized === 'org_credential_authorization.remove'
  ) {
    return 'pat_request_denied';
  }

  if (normalized.includes('personal_access_token_request')) {
    if (normalized.includes('approve')) return 'pat_request_approved';
    if (normalized.includes('deny') || normalized.includes('cancel')) return 'pat_request_denied';
    return 'pat_request_created';
  }

  if (normalized.includes('personal_access_token')) {
    if (normalized.includes('expire') || normalized.includes('expired')) return 'pat_expired';
  }

  if (normalized === 'team.create') return 'team_created';
  if (normalized === 'team.add_member') return 'team_member_added';
  if (normalized === 'team.remove_member') return 'team_member_removed';
  if (normalized === 'team.delete' || normalized === 'team.destroy') return 'team_deleted';

  return null;
}

function isPublicRepoAuditEntry(entry) {
  const data = entry?.data || {};
  const visibility = sanitizeString(
    data.visibility ||
    data.repository_visibility ||
    entry?.visibility ||
    entry?.repository_visibility
  );

  const publicFlag =
    typeof data.public === 'boolean'
      ? data.public
      : typeof entry?.public === 'boolean'
        ? entry.public
        : null;

  if (publicFlag === true) return true;
  if (visibility && visibility.toLowerCase() === 'public') return true;
  return false;
}

function parseFullRepoName(value) {
  const fullName = sanitizeString(value);
  if (!fullName || !fullName.includes('/')) {
    return {
      owner: null,
      name: fullName,
      fullName,
    };
  }

  const [owner, ...rest] = fullName.split('/');
  return {
    owner: sanitizeString(owner),
    name: sanitizeString(rest.join('/')),
    fullName,
  };
}

function extractAuditRepository(entry) {
  const data = entry?.data || {};
  const parsed = parseFullRepoName(
    data.repo || data.repository || entry?.repository || entry?.repo || entry?.repositoryName
  );

  const visibility = sanitizeString(
    data.visibility ||
    data.repository_visibility ||
    entry?.visibility ||
    entry?.repository_visibility
  );

  let isPrivate = null;
  if (typeof data.private === 'boolean') {
    isPrivate = data.private;
  } else if (typeof entry?.private === 'boolean') {
    isPrivate = entry.private;
  } else if (visibility) {
    isPrivate = visibility.toLowerCase() === 'private';
  }

  return {
    id: data.repository_id || data.repo_id || entry?.repository_id || null,
    name: parsed.name,
    fullName: parsed.fullName,
    url: sanitizeString(data.repository_url || entry?.repositoryUrl || data.url),
    ownerLogin: parsed.owner,
    visibility,
    isPrivate,
  };
}

function extractAuditTeamName(entry) {
  const data = entry?.data || {};
  return sanitizeString(data.team || data.team_name || entry?.teamName || entry?.team);
}

function getSignalSeverity(signalType) {
  switch (signalType) {
    case 'pat_no_expiry':
    case 'pat_over_permissive':
      return 'high';
    case 'pat_expired':
    case 'external_org_fork':
    case 'public_repo_created':
      return 'medium';
    default:
      return 'low';
  }
}

function buildAuditPhrase(since) {
  const from = toDate(since, new Date(Date.now() - 30 * 24 * 60 * 60 * 1000));
  const createdDate = from.toISOString().slice(0, 10);
  return `(action:personal_access_token OR action:org_credential_authorization OR action:team OR action:repo.create) created:>=${createdDate}`;
}

function extractNextLinkUrl(linkHeader) {
  if (!linkHeader || typeof linkHeader !== 'string') return null;

  const parts = linkHeader.split(',');
  for (const part of parts) {
    const section = part.trim();
    if (!section.includes('rel="next"')) continue;

    const match = section.match(/<([^>]+)>/);
    if (match && match[1]) return match[1];
  }

  return null;
}

async function fetchAuditCursorPage(token, login, { phrase, perPage = 100, order = 'desc', nextUrl = null }) {
  const requestConfig = {
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
    },
    timeout: 30000,
  };

  if (!nextUrl) {
    requestConfig.params = {
      phrase,
      per_page: perPage,
      order,
    };
  }

  debugLog('Fetching audit page via REST cursor flow', {
    login,
    phrase,
    perPage,
    order,
    hasNextUrl: Boolean(nextUrl),
  });

  const response = await axios.get(nextUrl || `https://api.github.com/orgs/${login}/audit-log`, requestConfig);

  const entries = Array.isArray(response?.data) ? response.data : [];
  const linkHeader = response?.headers?.link || response?.headers?.Link || '';
  const nextLinkUrl = extractNextLinkUrl(linkHeader);

  debugLog('Fetched audit cursor page result', {
    login,
    nodesCount: entries.length,
    hasNextPage: Boolean(nextLinkUrl),
  });

  return {
    nodes: entries,
    pageInfo: {
      hasNextPage: Boolean(nextLinkUrl),
      nextUrl: nextLinkUrl,
    },
  };
}

function isAuditLogUnavailableError(error) {
  const status = error?.response?.status;
  const message = String(error?.message || '');

  if (status === 401 || status === 403 || status === 404) {
    return true;
  }

  return (
    message.includes('FORBIDDEN') ||
    message.includes('NOT_FOUND') ||
    message.includes('Could not resolve to an Organization') ||
    message.includes('Resource not accessible') ||
    message.includes('Must have admin rights')
  );
}

function extractAuditPermissions(entry) {
  const data = entry?.data || {};
  return (
    data.permissions ||
    data.scopes ||
    data.repositories ||
    entry?.token_scopes ||
    data.token_scopes ||
    {}
  );
}

function extractAuditExpiresAt(entry) {
  const data = entry?.data || {};
  return toDate(
    data.expires_at ||
      data.expiration ||
      data.expired_at ||
      entry?.expires_at ||
      entry?.expiration ||
      entry?.expired_at,
    null
  );
}

function buildAuditDedupeKey(installationId, accountId, entry, signalType) {
  return buildDedupeKey('audit', installationId, accountId, [
    signalType,
    entry?._document_id || entry?.id || entry?.['@id'] || 'na',
    entry?.action || 'unknown-action',
    entry?.created_at || entry?.createdAt || 'unknown-time',
  ]);
}

async function syncOrganizationAuditSignals(SecurityEvent, { token, auditToken, installationId, accountId, login, since, tenantId }) {
  const effectiveToken = auditToken || process.env.GITHUB_ORG_AUDIT_TOKEN || token;

  if (!tenantId || !effectiveToken || !installationId || !accountId || !login) {
    debugLog('Skipping audit sync due to missing context', {
      hasTenantId: Boolean(tenantId),
      hasToken: Boolean(effectiveToken),
      installationId,
      accountId,
      login,
    });
    return { inserted: 0, skipped: true, reason: 'missing_context' };
  }

  const phrase = buildAuditPhrase(since);
  debugLog('Starting audit sync', {
    installationId,
    accountId,
    login,
    since: since || null,
    phrase,
  });

  let requestCount = 0;
  let inserted = 0;
  let hasNextPage = true;
  let nextUrl = null;

  while (hasNextPage && requestCount < 10) {
    let result;
    let matchedEntries = 0;
    let skippedUnmatchedEntries = 0;
    let pageBaseSignalsInserted = 0;
    let pageRiskSignalsInserted = 0;

    try {
      result = await fetchAuditCursorPage(effectiveToken, login, {
        phrase,
        perPage: 100,
        order: 'desc',
        nextUrl,
      });
    } catch (error) {
      if (isAuditLogUnavailableError(error)) {
        const status = error?.response?.status;
        const reason = status
          ? `audit_log_unavailable_${status}`
          : 'audit_log_unavailable_rest';

        debugLog('Audit sync unavailable for current auth/context', {
          installationId,
          accountId,
          login,
          reason,
          error: String(error?.message || error),
        });

        return {
          inserted,
          skipped: true,
          reason,
        };
      }
      throw error;
    }

    const entries = result.nodes;

    if (entries.length === 0) {
      debugLog('Audit sync page returned no entries', {
        installationId,
        accountId,
        login,
        requestCount,
      });
      break;
    }

    for (const entry of entries) {
      const action = sanitizeString(entry?.action);
      const normalizedAction = String(action || '').toLowerCase();
      let signalType = mapAuditActionToSignalType(action);

      if (!signalType && normalizedAction === 'repo.create' && isPublicRepoAuditEntry(entry)) {
        signalType = 'public_repo_created';
      }

      const tokenType = String(entry?.oauth_credential_type || entry?.data?.oauth_credential_type || '').toLowerCase();
      const isPatCredential = tokenType.includes('personal access token');
      const isPatAction = normalizedAction.includes('personal_access_token') || normalizedAction.includes('org_credential_authorization');

      if (
        !signalType &&
        !isPatAction &&
        !isPatCredential
      ) {
        skippedUnmatchedEntries += 1;
        continue;
      }

      matchedEntries += 1;

      const occurredAt = toDate(entry?.createdAt || entry?.created_at, new Date());

      if (signalType && !signalType.startsWith('pat_')) {
        await upsertSecurityEvent(SecurityEvent, {
          tenantId,
          installationId,
          accountId,
          login,
          source: 'audit',
          signalType,
          severity: getSignalSeverity(signalType),
          action,
          status: 'active',
          occurredAt,
          actor: {
            id: sanitizeString(entry?.actor_id),
            login: sanitizeString(entry?.actorLogin || entry?.actor),
          },
          organization: {
            id: accountId,
            login,
          },
          repository: extractAuditRepository(entry),
          metadata: {
            ...(entry?.data || {}),
            operationType: entry?.operationType || null,
            teamName: extractAuditTeamName(entry),
          },
          rawPayload: entry,
          dedupeKey: buildAuditDedupeKey(installationId, accountId, entry, signalType),
        });
        inserted += 1;
        pageBaseSignalsInserted += 1;
        continue;
      }

      const expiresAt = extractAuditExpiresAt(entry);
      const { normalized: permissions, writeLikeCount } = parsePatPermissions(extractAuditPermissions(entry));

      const hasExpiryInfo = expiresAt !== null;
      const hasPermissionInfo = Object.keys(permissions || {}).length > 0;

      const riskFlags = {
        hasNoExpiry: false,
        isExpired: hasExpiryInfo && expiresAt < new Date(),
        isOverPermissive: hasPermissionInfo && writeLikeCount >= OVER_PERMISSIVE_PAT_THRESHOLD,
      };

      const baseSignalType = signalType || 'pat_request_created';

      await upsertSecurityEvent(SecurityEvent, {
        tenantId,
        installationId,
        accountId,
        login,
        source: 'audit',
        signalType: baseSignalType,
        severity: baseSignalType === 'pat_request_denied' ? 'low' : 'medium',
        action,
        status: 'active',
        occurredAt,
        actor: {
          id: sanitizeString(entry?.actor_id),
          login: sanitizeString(entry?.actorLogin || entry?.actor),
        },
        organization: {
          id: accountId,
          login,
        },
        pat: {
          requestId: sanitizeString(entry?.data?.request_id || entry?.request_id || entry?.data?.id),
          tokenId: sanitizeString(entry?.data?.token_id || entry?.token_id || entry?.data?.id),
          expiresAt,
          permissions,
          hasNoExpiry: riskFlags.hasNoExpiry,
          isExpired: riskFlags.isExpired,
          isOverPermissive: riskFlags.isOverPermissive,
        },
        metadata: {
          ...(entry?.data || {}),
          operationType: entry?.operationType || null,
          entryType: entry?.__typename || null,
          repositoryName: entry?.repositoryName || null,
          repositoryUrl: entry?.repositoryUrl || null,
          teamName: entry?.teamName || null,
          organizationName: entry?.organizationName || null,
          writeLikePermissionCount: writeLikeCount,
        },
        rawPayload: entry,
        dedupeKey: buildAuditDedupeKey(installationId, accountId, entry, baseSignalType),
      });
      inserted += 1;
      pageBaseSignalsInserted += 1;

      if (riskFlags.hasNoExpiry) {
        await upsertSecurityEvent(SecurityEvent, {
          tenantId,
          installationId,
          accountId,
          login,
          source: 'audit',
          signalType: 'pat_no_expiry',
          severity: 'high',
          action,
          status: 'active',
          occurredAt,
          actor: { id: sanitizeString(entry?.actor_id), login: sanitizeString(entry?.actorLogin || entry?.actor) },
          organization: { id: accountId, login },
          pat: {
            requestId: sanitizeString(entry?.data?.request_id || entry?.request_id || entry?.data?.id),
            tokenId: sanitizeString(entry?.data?.token_id || entry?.token_id || entry?.data?.id),
            expiresAt,
            permissions,
            hasNoExpiry: true,
            isExpired: riskFlags.isExpired,
            isOverPermissive: riskFlags.isOverPermissive,
          },
          metadata: { ...entry?.data, writeLikePermissionCount: writeLikeCount },
          rawPayload: entry,
          dedupeKey: buildAuditDedupeKey(installationId, accountId, entry, 'pat_no_expiry'),
        });
        pageRiskSignalsInserted += 1;
      }

      if (riskFlags.isExpired) {
        await upsertSecurityEvent(SecurityEvent, {
          tenantId,
          installationId,
          accountId,
          login,
          source: 'audit',
          signalType: 'pat_expired',
          severity: 'medium',
          action,
          status: 'active',
          occurredAt,
          actor: { id: sanitizeString(entry?.actor_id), login: sanitizeString(entry?.actorLogin || entry?.actor) },
          organization: { id: accountId, login },
          pat: {
            requestId: sanitizeString(entry?.data?.request_id || entry?.request_id || entry?.data?.id),
            tokenId: sanitizeString(entry?.data?.token_id || entry?.token_id || entry?.data?.id),
            expiresAt,
            permissions,
            hasNoExpiry: riskFlags.hasNoExpiry,
            isExpired: true,
            isOverPermissive: riskFlags.isOverPermissive,
          },
          metadata: { ...entry?.data, writeLikePermissionCount: writeLikeCount },
          rawPayload: entry,
          dedupeKey: buildAuditDedupeKey(installationId, accountId, entry, 'pat_expired'),
        });
        pageRiskSignalsInserted += 1;
      }

      if (riskFlags.isOverPermissive) {
        await upsertSecurityEvent(SecurityEvent, {
          tenantId,
          installationId,
          accountId,
          login,
          source: 'audit',
          signalType: 'pat_over_permissive',
          severity: 'high',
          action,
          status: 'active',
          occurredAt,
          actor: { id: sanitizeString(entry?.actor_id), login: sanitizeString(entry?.actorLogin || entry?.actor) },
          organization: { id: accountId, login },
          pat: {
            requestId: sanitizeString(entry?.data?.request_id || entry?.request_id || entry?.data?.id),
            tokenId: sanitizeString(entry?.data?.token_id || entry?.token_id || entry?.data?.id),
            expiresAt,
            permissions,
            hasNoExpiry: riskFlags.hasNoExpiry,
            isExpired: riskFlags.isExpired,
            isOverPermissive: true,
          },
          metadata: { ...entry?.data, writeLikePermissionCount: writeLikeCount },
          rawPayload: entry,
          dedupeKey: buildAuditDedupeKey(installationId, accountId, entry, 'pat_over_permissive'),
        });
        pageRiskSignalsInserted += 1;
      }
    }

    debugLog('Processed audit sync page', {
      installationId,
      accountId,
      login,
      requestCount,
      entriesInPage: entries.length,
      matchedEntries,
      skippedUnmatchedEntries,
      pageBaseSignalsInserted,
      pageRiskSignalsInserted,
      totalBaseInserted: inserted,
    });

    hasNextPage = result.pageInfo.hasNextPage;
    nextUrl = result.pageInfo.nextUrl || null;
    requestCount += 1;
  }

  debugLog('Completed audit sync', {
    installationId,
    accountId,
    login,
    inserted,
    skipped: false,
    reason: null,
  });

  return { inserted, skipped: false, reason: null };
}

async function getSecuritySignalTotals(SecurityEvent, installationId, accountId, tenantId = null) {
  if (!installationId || !accountId) {
    return {
      totalSecurityEvents: 0,
      totalPatNoExpiry: 0,
      totalPatExpired: 0,
      totalPatOverPermissive: 0,
      totalExternalForks: 0,
    };
  }

  const match = { installationId, accountId };
  if (tenantId) match.tenantId = tenantId;

  const aggregated = await SecurityEvent.aggregate([
    { $match: match },
    { $group: { _id: '$signalType', count: { $sum: 1 } } },
  ]);

  const byType = aggregated.reduce((map, item) => {
    map[item._id] = item.count;
    return map;
  }, {});

  const totalSecurityEvents = Object.values(byType).reduce((sum, value) => sum + value, 0);

  return {
    totalSecurityEvents,
    totalPatNoExpiry: byType.pat_no_expiry || 0,
    totalPatExpired: byType.pat_expired || 0,
    totalPatOverPermissive: byType.pat_over_permissive || 0,
    totalExternalForks: byType.external_org_fork || 0,
  };
}

module.exports = {
  ingestPatRequestWebhook,
  ingestForkWebhook,
  syncOrganizationAuditSignals,
  getSecuritySignalTotals,
};
