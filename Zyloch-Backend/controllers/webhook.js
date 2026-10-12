const axios = require('axios');
const createError = require('../utils/createError');
const ghappClient = require('../helpers/ghappClient');
const summaryQueue = require('../queues/summaryQueue');
const { findLiveRun } = require('../services/summaryRuns');
const { getControlModels } = require('../db/controlModels');
const { getTenantModels } = require('../db/tenantModels');
const { fetchRepositoryBranches } = require('../helpers/branchFetch');
const { resolveTenantByIdentity, getTenantByInstallationId } = require('../services/authRouting');
const {
  ingestPatRequestWebhook,
  ingestForkWebhook,
  getSecuritySignalTotals,
} = require('../helpers/securitySignalsHelper');
const { resolveTenantLimits, capReposToLimit } = require('../services/licenseLimits');
const { fetchInstallationRepositories, toRepoNames } = require('../helpers/installationRepos');

/**
 * KAN-39 / Strategy C tenant resolution for webhooks.
 *
 * Linked installations: resolve `tenantId` from control-plane `installation_index`
 * via `getTenantByInstallationId` (NOT legacy `Installation.zylochOrganizationId`).
 * All derived writes (repo / team / security / summary) must include that `tenantId`.
 *
 * Unlinked installations (no index row):
 * - Log a warning (no tenant DB writes).
 * - Enqueue a control-plane `platform_events` row (`installation.webhook_unlinked`)
 *   as an admin-link work queue (tenantId null). Consumed later by admin link UI (MT-028).
 * - Return HTTP 200 so GitHub does not retry.
 *
 * See docs/multi-tenant/WEBHOOK_TENANT_LINKING.md.
 */

/**
 * Resolve the tenant (+ its scoped models) that owns a GitHub installation.
 * Returns null when the installation is not mapped to any tenant yet.
 */
async function resolveTenantByInstallation(installationId) {
  const tenantId = await getTenantByInstallationId(installationId);
  if (!tenantId) return null;
  return { tenantId, models: getTenantModels(tenantId) };
}

/**
 * Refresh a repository's branch list after a push (main #371), tenant-scoped.
 *
 * The original wrote through a global `RepositoryData` model. Under Strategy C the
 * document lives in the owning tenant's database, so the installation is resolved
 * to its tenant first and the write goes through that tenant's models. A push from
 * an installation that is not linked to any tenant is skipped — there is no tenant
 * to write to, and guessing one would be a cross-tenant write.
 */
async function refreshRepositoryBranchesFromPush(body) {
  const installationId = body.installation?.id;
  const repository = body.repository;
  const owner = repository?.owner?.login;
  const name = repository?.name;

  if (!Number.isInteger(installationId) || !owner || !name) {
    console.warn('[Webhook] Cannot refresh branches from push: incomplete repository or installation data');
    return;
  }

  const scope = await resolveTenantByInstallation(installationId);
  if (!scope) {
    console.warn(
      `[Webhook] Skipping branch refresh for ${owner}/${name}: installation ${installationId} is not linked to a tenant`
    );
    return;
  }

  // Required lazily: config/github.js calls process.exit(1) at import when the
  // GitHub App env vars are absent, which would take down anything that merely
  // requires this controller (tests included). Same pattern as githubMembership.js.
  const { getInstallationToken } = require('../helpers/githubTokenHelper');
  const token = await getInstallationToken(installationId);
  const { branches, staleBranchCount } = await fetchRepositoryBranches(
    token,
    owner,
    name,
    repository.archived || false,
    true
  );

  const updatedRepository = await scope.models.RepositoryData.findOneAndUpdate(
    { installationId, repositoryName: name, owner },
    { branches, staleBranchCount, lastActive: new Date() },
    { new: true }
  );

  if (!updatedRepository) {
    console.warn(`[Webhook] Repository ${owner}/${name} not found while refreshing branches after push`);
    return;
  }

  console.log(
    `[Webhook] Refreshed ${branches.length} active branches for ${owner}/${name} after push (tenant ${scope.tenantId})`
  );
}

/**
 * Log + optional admin-link queue for webhooks whose installation is not linked.
 * @returns {object} JSON body for a 200 response
 */
async function handleUnlinkedInstallation({
  event,
  installationId,
  deliveryId = null,
  action = null,
  accountLogin = null,
  installerEmail = null,
  reason = 'not_in_installation_index',
}) {
  // Structured ops log (KAN-52) — queryable in log backends by metric + installationId
  console.warn(
    JSON.stringify({
      level: 'warn',
      metric: 'installation.webhook_unlinked',
      msg: 'Unlinked installation — skipping tenant writes',
      event,
      installationId,
      deliveryId,
      action,
      accountLogin,
      installerEmail,
      reason,
      adminLinkRequired: true,
    })
  );

  try {
    const { PlatformEvent } = getControlModels();
    await PlatformEvent.create({
      tenantId: null,
      eventType: 'installation.webhook_unlinked',
      payload: {
        installationId: installationId ?? null,
        githubEvent: event,
        deliveryId,
        action,
        accountLogin,
        installerEmail,
        reason,
        adminLinkRequired: true,
      },
      occurredAt: new Date(),
    });
  } catch (err) {
    console.error('[Webhook] Failed to queue unlinked installation for admin link:', err.message);
  }

  return {
    status: 'ok',
    note: 'unlinked_installation',
    message: 'Installation is not linked to a Zyloch tenant; event logged for admin link',
  };
}

/**
 * When installation.created cannot be routed to a tenant admin, log + queue for admin link.
 */
async function handlePendingInstallationLink({
  installationId,
  deliveryId,
  senderLogin,
  accountLogin,
  installerEmail = null,
}) {
  console.warn(
    JSON.stringify({
      level: 'warn',
      metric: 'installation.pending_link',
      msg: 'Installation created but not linked to a tenant',
      installationId,
      deliveryId,
      senderLogin,
      accountLogin,
      installerEmail,
      adminLinkRequired: true,
    })
  );

  try {
    const { PlatformEvent } = getControlModels();
    await PlatformEvent.create({
      tenantId: null,
      eventType: 'installation.pending_link',
      payload: {
        installationId: installationId ?? null,
        deliveryId,
        senderLogin,
        accountLogin,
        installerEmail,
        adminLinkRequired: true,
      },
      occurredAt: new Date(),
    });
  } catch (err) {
    console.error('[Webhook] Failed to queue pending installation link:', err.message);
  }

  return {
    status: 'ok',
    note: 'pending_admin_link',
    message: 'Installer could not be routed to a tenant; queued for admin link',
  };
}

/**
 * Resolve the repository inventory to record for an installation, capped to the
 * tenant's plan.
 *
 * The webhook payload is not a dependable inventory for a large installation.
 * An app installed on "All repositories" reports `repository_selection: "all"`
 * and the `repositories` array riding along with the event is a snapshot that
 * GitHub trims to keep the delivery under its 25MB ceiling — for an org with
 * thousands of repos it arrives partial, or not at all. When the selection is
 * "all" (or the array is missing) the list is read from
 * `GET /installation/repositories` instead, which is paginated and reports the
 * true `total_count`.
 *
 * The only ceiling applied is the tenant plan's `maxRepos` from
 * `license_plans` (Basic 2000 / Pro 5000 today) — there is deliberately no
 * constant here to drift away from the catalog. A plan whose `maxRepos` is
 * negative is UNLIMITED and keeps everything. When the plan cannot be read at
 * all, the payload list is stored as delivered and `repoLimit` left null rather
 * than guessing a cap in either direction; the ingestion cap enforced by
 * jobs/fetchInstallationSummary.js still applies to what actually gets scanned.
 */
async function resolveInstallationRepos(installation, payloadRepositories, tenantId) {
  const selection = installation?.repository_selection === 'all' ? 'all' : 'selected';
  const payloadNames = toRepoNames(payloadRepositories);

  let maxRepos = Number.POSITIVE_INFINITY;
  let planId = null;
  let planResolved = false;
  try {
    const limits = await resolveTenantLimits(tenantId);
    maxRepos = limits.maxRepos;
    planId = limits.planId;
    planResolved = true;
  } catch (error) {
    console.error(
      `[Webhook] Could not resolve license limits for tenant ${tenantId}: ${error.message} — ` +
        'storing the payload repository list uncapped'
    );
  }

  let names = payloadNames;
  let totalCount = payloadNames.length;
  let source = 'webhook_payload';

  // Only worth an API round trip when the payload cannot be trusted to be whole.
  if (planResolved && (selection === 'all' || payloadNames.length === 0)) {
    try {
      // Required lazily: config/github.js calls process.exit(1) at import when the
      // GitHub App env vars are absent (same reason as the push handler above).
      const { getInstallationToken } = require('../helpers/githubTokenHelper');
      const token = await getInstallationToken(installation.id);
      const result = await fetchInstallationRepositories(token, { limit: maxRepos });
      names = toRepoNames(result.repositories);
      totalCount = result.totalCount;
      source = 'github_api';
    } catch (error) {
      console.error(
        `[Webhook] Failed to list repositories for installation ${installation?.id} from the GitHub API: ` +
          `${error.message} — falling back to the ${payloadNames.length} repositories in the payload`
      );
    }
  }

  const repos = planResolved ? capReposToLimit(names, maxRepos) : names;
  if (totalCount < repos.length) totalCount = repos.length;

  return {
    repos,
    totalCount,
    selection,
    planId,
    source,
    limit: planResolved && Number.isFinite(maxRepos) ? maxRepos : null,
    truncated: totalCount > repos.length,
  };
}

/**
 * Apply an `installation_repositories` add/remove to the stored inventory.
 *
 * Additions used to be dropped entirely — only removals were applied — so
 * `Installation.repos` drifted away from GitHub as soon as a repo was granted.
 * The merged list is capped by the tenant plan's `maxRepos`, exactly as it is on
 * install, while `repoCount` keeps tracking the installation's real size so a
 * capped list is still reported as over-plan rather than as complete.
 */
async function reconcileInstallationRepos({
  models,
  tenantId,
  installationId,
  accountLogin,
  added = [],
  removed = [],
}) {
  const installation = await models.Installation.findOne({ installationId });
  if (!installation) {
    console.warn(
      `[Webhook] Installation ${installationId} not found while reconciling its repository list`
    );
    return;
  }

  const removedNames = new Set(toRepoNames(removed));
  const addedNames = toRepoNames(added);
  const existing = installation.repos || [];
  const selection = installation.selectedRepos || [];
  const hasSelection = selection.length > 0;

  // With an explicit allowlist, a repository newly granted on GitHub does NOT
  // join the monitored set on its own — the tenant chose what to monitor, and an
  // org that keeps creating repositories would otherwise quietly eat the plan's
  // remaining headroom. It still counts towards `repoCount`, which is what puts
  // the installation back in front of the chooser once it exceeds the plan.
  const seen = new Set();
  const merged = [];
  for (const name of hasSelection ? selection : [...existing, ...addedNames]) {
    if (removedNames.has(name) || seen.has(name)) continue;
    seen.add(name);
    merged.push(name);
  }

  let planId = null;
  let limit = installation.repoLimit ?? null;
  let repos = merged;
  try {
    const limits = await resolveTenantLimits(tenantId);
    planId = limits.planId;
    limit = Number.isFinite(limits.maxRepos) ? limits.maxRepos : null;
    repos = capReposToLimit(merged, limits.maxRepos);
  } catch (error) {
    console.error(
      `[Webhook] Could not resolve license limits for tenant ${tenantId}: ${error.message} — ` +
        'repository list left uncapped'
    );
  }

  // The stored list may already be capped, so the previous total — not its
  // length — is what the delta applies to.
  const previousTotal = Math.max(Number(installation.repoCount) || 0, existing.length);
  const totalCount = Math.max(
    previousTotal + addedNames.length - removedNames.size,
    repos.length
  );
  const truncated = totalCount > repos.length;

  await models.Installation.findOneAndUpdate(
    { installationId },
    {
      // Without a selection, an over-limit installation keeps no names — only
      // the count — until the customer chooses (see installation.created).
      repos: truncated && !hasSelection ? [] : repos,
      repoCount: totalCount,
      repoLimit: limit,
      reposTruncated: truncated,
      // A removed repository leaves the allowlist too, or the next save would be
      // rejected for naming a repository the installation can no longer reach.
      ...(hasSelection ? { selectedRepos: repos } : {}),
    }
  );

  if (truncated) {
    await reportRepoLimitBreach({
      tenantId,
      installationId,
      accountLogin,
      scope: {
        repos,
        storedCount: hasSelection ? repos.length : 0,
        totalCount,
        selection: installation.repositorySelection || 'selected',
        planId,
        limit,
      },
    });
  }
}

/**
 * Record that an installation holds more repositories than its plan allows.
 *
 * The installation is still stored — refusing it would leave the org invisible
 * in Zyloch with no explanation — but the breach is logged and queued so
 * billing/support can see which tenants are over, and by how much.
 */
async function reportRepoLimitBreach({ tenantId, installationId, accountLogin, scope }) {
  console.warn(
    JSON.stringify({
      level: 'warn',
      metric: 'installation.repo_limit_exceeded',
      msg: 'Installation has more repositories than the plan allows — selection required',
      tenantId: String(tenantId),
      installationId,
      accountLogin,
      planId: scope.planId,
      limit: scope.limit,
      totalRepositories: scope.totalCount,
      storedRepositories: scope.storedCount ?? scope.repos.length,
    })
  );

  try {
    const { PlatformEvent } = getControlModels();
    await PlatformEvent.create({
      tenantId,
      eventType: 'installation.repo_limit_exceeded',
      payload: {
        installationId,
        accountLogin,
        planId: scope.planId,
        limit: scope.limit,
        totalRepositories: scope.totalCount,
        storedRepositories: scope.storedCount ?? scope.repos.length,
        repositorySelection: scope.selection,
      },
      occurredAt: new Date(),
    });
  } catch (err) {
    console.error('[Webhook] Failed to queue repo limit event:', err.message);
  }
}

/**
 * Recalculate and persist the InstallationSummaryJob aggregate from current
 * tenant-scoped data. Non-critical: never throws.
 */
async function updateInstallationSummary(models, installationId, accountId) {
  try {
    const { InstallationSummaryJob, RepositoryData, Team, TeamMember, GitHubSecurityEvent, tenantId } = models;

    const job = await InstallationSummaryJob.findOne({
      tenantId,
      installationId,
      accountId,
      status: 'completed',
    }).sort({ updatedAt: -1 });

    if (!job || !job.summary) {
      console.log(`[Webhook] No completed job for installation ${installationId}, skipping summary update`);
      return;
    }

    const repositories = await RepositoryData.find({ tenantId, installationId, accountId });
    if (repositories.length === 0) {
      console.log(`[Webhook] No repositories for installation ${installationId}`);
      return;
    }

    const totalBranches = repositories.reduce((sum, repo) => sum + (repo.branches?.length || 0), 0);
    const totalCommits = repositories.reduce((sum, repo) => sum + (repo.totalCommits || 0), 0);
    const totalForks = repositories.reduce((sum, repo) => sum + (repo.forks || 0), 0);
    const totalStars = repositories.reduce((sum, repo) => sum + (repo.stars || 0), 0);
    const totalPrivate = repositories.filter((repo) => repo.isPrivate).length;
    const totalPublic = repositories.length - totalPrivate;
    const totalArchivedRepos = repositories.filter((repo) => repo.isArchived).length;
    const totalStaleBranches = repositories.reduce((sum, repo) => sum + (repo.staleBranchCount || 0), 0);
    const securityTotals = await getSecuritySignalTotals(GitHubSecurityEvent, installationId, accountId, tenantId);

    const languages = job.summary.languages || [];
    const totalBytes = job.summary.totals?.totalBytes || 0;

    const updatedRepositories = repositories
      .map((repo) => ({
        name: repo.repositoryName,
        url: repo.repositoryUrl,
        stars: repo.stars || 0,
        forks: repo.forks || 0,
        isPrivate: repo.isPrivate || false,
        branches: repo.branches?.length || 0,
        commits: repo.totalCommits || 0,
        lastCommit: repo.branches?.[0]?.target?.committedDate || null,
        lastActive: repo.lastActive,
      }))
      .sort((a, b) => new Date(b.lastActive) - new Date(a.lastActive));

    const teams = await Team.find({ tenantId, installationId, accountId });
    const totalTeams = teams.length;
    const totalTeamMembers = await TeamMember.countDocuments({ tenantId, installationId, accountId });
    const teamsData = teams.map((team) => ({
      teamId: team.teamId,
      teamName: team.teamName,
      teamSlug: team.teamSlug,
      memberCount: team.memberCount,
      repositoriesCount: team.repositoriesCount,
    }));

    const updatedSummary = {
      totals: {
        totalRepositories: repositories.length,
        totalBranches,
        totalCommits,
        totalForks,
        totalStars,
        totalPrivate,
        totalPublic,
        totalInternal: job.summary.totals?.totalInternal || 0,
        totalBytes,
        totalArchivedRepos,
        totalStaleBranches,
        totalTeams,
        totalTeamMembers,
        totalSecurityEvents: securityTotals.totalSecurityEvents,
        totalPatNoExpiry: securityTotals.totalPatNoExpiry,
        totalPatExpired: securityTotals.totalPatExpired,
        totalPatOverPermissive: securityTotals.totalPatOverPermissive,
        totalExternalForks: securityTotals.totalExternalForks,
      },
      languages,
      repositories: updatedRepositories,
      teams: teamsData,
    };

    await InstallationSummaryJob.findByIdAndUpdate(job._id, {
      summary: updatedSummary,
      updatedAt: new Date(),
    });
    console.log(`[Webhook] Summary updated for installation ${installationId}`);
  } catch (error) {
    console.error('[Webhook] Error updating installation summary:', error.message);
  }
}

/**
 * Forward a code event to the scan service.
 *
 * Uses the shared `ghappClient` base-URL resolution (MT-13.1). This used to fall
 * back to a hardcoded public IP, which both pinned traffic to one host and
 * quietly sent webhook payloads over plain HTTP to an address no config
 * controlled. With no configuration the shared resolver points at the internal
 * compose service name instead.
 *
 * The GitHub signature headers are passed through unchanged: GHAPP authenticates
 * this route by HMAC, not by the internal service key.
 */
async function forwardToGHAPPBackend(event, body, headers, rawBody) {
  try {
    const webhookUrl = `${ghappClient.getGhappBaseUrl()}/webhook/github`;
    console.log(`[Webhook] Forwarding ${event} event to GHAPP backend: ${webhookUrl}`);

    const payload = rawBody || JSON.stringify(body);
    const response = await axios.post(webhookUrl, payload, {
      headers: {
        'X-GitHub-Event': headers['x-github-event'] || event,
        'X-Hub-Signature-256': headers['x-hub-signature-256'] || '',
        'Content-Type': 'application/json',
      },
      timeout: 10000,
    });
    console.log(`[Webhook] Successfully forwarded ${event} event to GHAPP backend`);
    return response.data;
  } catch (error) {
    console.error(`[Webhook] Error forwarding ${event} event to GHAPP backend:`, error.message);
    return null;
  }
}

/** Queue an incremental refresh for a tenant installation. */
async function triggerIncrementalRefresh(models, tenantId, installationId, accountId, login, accountType) {
  try {
    const { InstallationSummaryJob } = models;

    // A sync already queued or running will pick this change up, or the next push
    // will. Queueing another here reset the running sync's progress to 0 and
    // raced it on the same document.
    const existingJob = await InstallationSummaryJob.findOne({ tenantId, installationId, accountId });
    if (await findLiveRun(summaryQueue, existingJob)) {
      console.log(`[Webhook] Sync already running for installation ${installationId}; refresh not queued`);
      return;
    }

    const job = await InstallationSummaryJob.findOneAndUpdate(
      { tenantId, installationId, accountId },
      {
        // `tenantId` must not repeat in `$set` — MongoDB rejects a path written
        // by two operators ("would create a conflict at 'tenantId'").
        $setOnInsert: { tenantId, installationId, login, accountId, accountType, createdAt: new Date() },
        $set: { status: 'pending', progress: 0, error: null, updatedAt: new Date() },
      },
      { upsert: true, new: true }
    );

    const bullJob = await summaryQueue.add(
      'process-installation',
      {
        tenantId: String(tenantId),
        installationId,
        login,
        accountId,
        accountType,
        mongoJobId: job._id,
        isIncremental: true,
      },
      { jobId: `webhook-refresh-${installationId}-${Date.now()}`, priority: 3 }
    );

    await InstallationSummaryJob.findByIdAndUpdate(job._id, { bullmqJobId: bullJob.id });
    console.log(`[Webhook] Incremental refresh queued: ${bullJob.id}`);
  } catch (error) {
    console.error('[Webhook] Error triggering incremental refresh:', error.message);
  }
}

async function handleWebhook(req, res, next) {
  try {
    const event = req.headers['x-github-event'];
    const deliveryId = req.headers['x-github-delivery'];
    const body = req.body;

    console.log(`GitHub Webhook received: ${event}`);

    if (!event) return next(createError(400, 'Missing event header'));

    // --- Code events: just forward to scan service (no tenant DB writes) ---
    if (event === 'push' || event === 'pull_request') {
      // The scan service needs a tenant to write results into and refuses an
      // unlinked installation, so forwarding one only produced a failed request
      // on both sides for every push. Handled like the other unlinked events.
      const installationId = body?.installation?.id;
      const route = installationId ? await resolveTenantByInstallation(installationId) : null;
      if (!route) {
        return res.status(200).json(
          await handleUnlinkedInstallation({
            event,
            installationId,
            deliveryId,
            accountLogin: body?.repository?.owner?.login || body?.installation?.account?.login,
          })
        );
      }

      // Branch refresh on push (main #371), tenant-scoped: the write targets the
      // owning tenant's RepositoryData, resolved through installation_index. An
      // unlinked installation is skipped rather than written to a global model.
      if (event === 'push') {
        refreshRepositoryBranchesFromPush(body).catch((err) => {
          const repo = body.repository;
          const repoFullName = repo
            ? `${repo.owner?.login || 'unknown'}/${repo.name || 'unknown'}`
            : 'unknown';
          console.error(`[Webhook] Failed to refresh branches for ${repoFullName}:`, err.message);
        });
      }

      const rawBody = req.rawBody || null;
      forwardToGHAPPBackend(event, body, req.headers, rawBody).catch((err) => {
        console.error(`[Webhook] Failed to forward ${event} event:`, err.message);
      });
      return res.status(200).json({ status: 'ok', message: 'Event forwarded to scan service', event });
    }

    // --- Personal Access Token Request Events ---
    if (event === 'personal_access_token_request') {
      const installationId = body?.installation?.id;
      const route = installationId ? await resolveTenantByInstallation(installationId) : null;
      if (!route) {
        return res.status(200).json(
          await handleUnlinkedInstallation({
            event,
            installationId,
            deliveryId,
            accountLogin: body?.organization?.login || body?.installation?.account?.login,
          })
        );
      }

      const result = await ingestPatRequestWebhook(
        route.models.GitHubSecurityEvent,
        body,
        deliveryId,
        route.tenantId
      );
      if (result.installationId && result.accountId) {
        await updateInstallationSummary(route.models, result.installationId, result.accountId);
      }
      return res.status(200).json({ status: 'ok', inserted: result.inserted });
    }

    // --- Fork Events (only external forks are stored) ---
    if (event === 'fork') {
      const installationId = body?.installation?.id;
      const route = installationId ? await resolveTenantByInstallation(installationId) : null;
      if (!route) {
        return res.status(200).json(
          await handleUnlinkedInstallation({
            event,
            installationId,
            deliveryId,
            accountLogin: body?.organization?.login || body?.installation?.account?.login,
          })
        );
      }

      const result = await ingestForkWebhook(
        route.models.GitHubSecurityEvent,
        body,
        deliveryId,
        route.tenantId
      );
      if (result.installationId && result.accountId) {
        await updateInstallationSummary(route.models, result.installationId, result.accountId);
      }
      return res.status(200).json({ status: 'ok', inserted: result.inserted });
    }

    // --- Installation Events ---
    if (event === 'installation') {
      const { action, installation, repositories = [], sender } = body;
      console.log(`Installation event: ${action} for ${installation?.id} by ${sender?.login}`);

      if (!installation || !installation.account) {
        return next(createError(400, 'Invalid payload: missing installation or account'));
      }

      if (action === 'created') {
        // Resolve the installer's tenant via the control-plane identity table.
        let tenantId = null;
        let models = null;
        let linkedBy = null;

        let installerEmail = null;
        if (sender && sender.id) {
          try {
            const identity = await resolveTenantByIdentity('github', sender.id);
            if (identity) {
              const tModels = getTenantModels(identity.tenantId);
              const installerUser = await tModels.User.findById(identity.userId).select('role email');
              installerEmail = installerUser?.email || null;
              if (installerUser && installerUser.role === 'admin') {
                tenantId = identity.tenantId;
                models = tModels;
                linkedBy = {
                  userId: installerUser._id,
                  userEmail: installerUser.email,
                  linkedAt: new Date(),
                };
              } else {
                console.log(`Installer ${sender.login} is not an admin — installation not stored`);
              }
            } else {
              console.log(`Installer ${sender.login} not found in control plane — installation not stored`);
            }
          } catch (error) {
            console.error(`Error resolving installer tenant: ${error.message}`);
          }
        }

        if (!tenantId) {
          return res.status(200).json(
            await handlePendingInstallationLink({
              installationId: installation.id,
              deliveryId,
              senderLogin: sender?.login || null,
              accountLogin: installation.account?.login || null,
              installerEmail,
            })
          );
        }

        // Never derive the repo list straight from `repositories`: for an
        // "All repositories" install on a large org that array is partial (or
        // absent), which is what left big orgs showing "no installation".
        const repoScope = await resolveInstallationRepos(installation, repositories, tenantId);
        if (repoScope.truncated) {
          await reportRepoLimitBreach({
            tenantId,
            installationId: installation.id,
            accountLogin: installation.account?.login || null,
            scope: { ...repoScope, storedCount: 0 },
          });
        }

        await models.Installation.findOneAndUpdate(
          { installationId: installation.id },
          {
            installationId: installation.id,
            account: installation.account,
            // Over the plan limit nothing is chosen yet, so no repository names
            // are kept — only the count, which is what puts the chooser up.
            // Storing the first N the API returned meant keeping repositories
            // the customer never picked. Within the limit, all are monitored.
            repos: repoScope.truncated ? [] : repoScope.repos,
            repositorySelection: repoScope.selection,
            repoCount: repoScope.totalCount,
            repoLimit: repoScope.limit,
            reposTruncated: repoScope.truncated,
            installer: sender && {
              id: sender.id,
              login: sender.login,
              avatarUrl: sender.avatar_url,
              profileUrl: sender.html_url,
            },
            linkedBy,
            lastFetchedAt: new Date(),
          },
          { upsert: true, new: true }
        );

        const { InstallationIndex } = getControlModels();
        await InstallationIndex.updateOne(
          { githubInstallationId: installation.id },
          {
            $set: {
              tenantId,
              accountLogin: installation.account.login,
              accountType: installation.account.type,
              linkedAt: new Date(),
            },
          },
          { upsert: true }
        );

        console.log(
          `Installation ${installation.id} stored for tenant ${tenantId} — ` +
            `${repoScope.repos.length}/${repoScope.totalCount} repositories ` +
            `(selection=${repoScope.selection}, source=${repoScope.source}, ` +
            `plan=${repoScope.planId || 'none'}, limit=${repoScope.limit ?? 'unknown'})`
        );
      } else if (action === 'deleted') {
        const route = await resolveTenantByInstallation(installation.id);
        if (route) {
          const { tenantId, models } = route;
          const existing = await models.Installation.find({ installationId: installation.id });

          const { PlatformEvent, InstallationIndex } = getControlModels();
          for (const item of existing) {
            await PlatformEvent.create({
              tenantId,
              eventType: 'installation.removed',
              payload: {
                installationId: item.installationId,
                accountLogin: item.account?.login,
                snapshot: {
                  installationId: item.installationId,
                  account: item.account,
                  repos: item.repos,
                },
              },
              occurredAt: new Date(),
            });
          }

          await models.Installation.deleteMany({ installationId: installation.id });
          await InstallationIndex.deleteOne({ githubInstallationId: installation.id });
          console.log(`Installation ${installation.id} deleted for tenant ${tenantId}`);
        } else {
          await handleUnlinkedInstallation({
            event,
            installationId: installation.id,
            deliveryId,
            action,
            accountLogin: installation.account?.login,
            reason: 'delete_for_unknown_installation',
          });
        }
      }

      return res.status(200).json({ status: 'ok' });
    }

    // --- Repositories Added/Removed ---
    if (event === 'installation_repositories') {
      const installationId = body.installation?.id;
      const accountId = body.installation?.account?.id;
      const login = body.installation?.account?.login;

      if (!Number.isInteger(installationId) || installationId <= 0) {
        return next(createError(400, 'Invalid payload: installationId must be a positive integer'));
      }
      if (!Number.isInteger(accountId) || accountId <= 0) {
        return next(createError(400, 'Invalid payload: accountId must be a positive integer'));
      }
      if (!login || typeof login !== 'string' || login.trim().length === 0) {
        return next(createError(400, 'Invalid payload: login must be a non-empty string'));
      }

      const route = await resolveTenantByInstallation(installationId);
      if (!route) {
        return res.status(200).json(
          await handleUnlinkedInstallation({
            event,
            installationId,
            deliveryId,
            accountLogin: login,
          })
        );
      }
      const { tenantId, models } = route;

      const repositoriesAdded = body.repositories_added || [];
      const repositoriesRemoved = body.repositories_removed || [];
      const added = repositoriesAdded.length;
      const removed = repositoriesRemoved.length;

      if (removed > 0) {
        for (const repo of repositoriesRemoved) {
          const [owner, name] = repo.full_name.split('/');
          try {
            await models.RepositoryData.deleteOne({
              tenantId,
              installationId,
              accountId,
              repositoryName: name,
              owner,
            });
            console.log(`[Webhook] Deleted ${repo.full_name} from RepositoryData`);
          } catch (error) {
            console.error(`[Webhook] Error deleting ${repo.full_name}:`, error.message);
          }
        }
      }

      if (added > 0 || removed > 0) {
        await reconcileInstallationRepos({
          models,
          tenantId,
          installationId,
          accountLogin: login,
          added: repositoriesAdded,
          removed: repositoriesRemoved,
        });
      }

      if (accountId && login && (added > 0 || removed > 0)) {
        const accountType = body.installation?.account?.type || 'User';
        await triggerIncrementalRefresh(models, tenantId, installationId, accountId, login, accountType);
      }

      return res.status(200).json({ status: 'ok' });
    }

    // --- Repository Events (archived, renamed, visibility) ---
    if (event === 'repository') {
      const { action, repository, installation } = body;
      if (!repository || !installation) {
        return next(createError(400, 'Invalid payload: missing repository or installation'));
      }

      const installationId = installation.id;
      const accountId = repository.owner.id;
      const [owner, name] = repository.full_name.split('/');

      const route = await resolveTenantByInstallation(installationId);
      if (!route) {
        return res.status(200).json(
          await handleUnlinkedInstallation({
            event,
            installationId,
            deliveryId,
            action,
            accountLogin: repository.owner?.login,
          })
        );
      }
      const { tenantId, models } = route;

      if (action === 'archived' || action === 'unarchived') {
        const isArchived = action === 'archived';
        try {
          await models.RepositoryData.findOneAndUpdate(
            { tenantId, installationId, accountId, repositoryName: name, owner },
            { $set: { isArchived, lastActive: new Date(), tenantId } },
            { new: true }
          );
        } catch (error) {
          console.error(`[Webhook] Error updating archived status for ${repository.full_name}:`, error.message);
        }
      }

      if (action === 'renamed' && body.changes?.repository?.name?.from) {
        const oldName = body.changes.repository.name.from;
        try {
          await models.RepositoryData.findOneAndUpdate(
            { tenantId, installationId, accountId, repositoryName: oldName, owner },
            {
              $set: {
                tenantId,
                repositoryName: name,
                repositoryUrl: repository.html_url,
                lastActive: new Date(),
              },
            },
            { new: true }
          );
        } catch (error) {
          console.error(`[Webhook] Error renaming repository ${oldName} to ${name}:`, error.message);
        }
      }

      if (action === 'publicized' || action === 'privatized') {
        const isPrivate = action === 'privatized';
        try {
          await models.RepositoryData.findOneAndUpdate(
            { tenantId, installationId, accountId, repositoryName: name, owner },
            { $set: { isPrivate, lastActive: new Date(), tenantId } },
            { new: true }
          );
        } catch (error) {
          console.error(`[Webhook] Error updating visibility for ${repository.full_name}:`, error.message);
        }
      }

      return res.status(200).json({ status: 'ok' });
    }

    // --- Team Events ---
    if (event === 'team') {
      const { action, team, organization, installation } = body;
      if (!team || !organization || !installation) {
        return next(createError(400, 'Invalid payload: missing team, organization, or installation'));
      }

      const installationId = installation.id;
      const accountId = organization.id;
      const login = organization.login;

      const route = await resolveTenantByInstallation(installationId);
      if (!route) {
        return res.status(200).json(
          await handleUnlinkedInstallation({
            event,
            installationId,
            deliveryId,
            action,
            accountLogin: login,
          })
        );
      }
      const { tenantId, models } = route;

      if (action === 'created' || action === 'edited') {
        try {
          await models.Team.findOneAndUpdate(
            { tenantId, installationId, accountId, teamId: team.node_id },
            {
              tenantId,
              installationId,
              accountId,
              login,
              teamId: team.node_id,
              teamName: team.name,
              teamSlug: team.slug,
              description: team.description || null,
              privacy: team.privacy?.toUpperCase() || 'SECRET',
              memberCount: team.members_count || 0,
              repositoriesCount: team.repos_count || 0,
            },
            { upsert: true, new: true }
          );
        } catch (error) {
          console.error(`[Webhook] Error ${action} team ${team.name}:`, error.message);
        }
      }

      if (action === 'deleted') {
        try {
          await models.Team.deleteOne({ tenantId, installationId, accountId, teamId: team.node_id });
          await models.TeamMember.deleteMany({ tenantId, installationId, accountId, teamId: team.node_id });
        } catch (error) {
          console.error(`[Webhook] Error deleting team ${team.name}:`, error.message);
        }
      }

      if (action === 'added_to_repository' || action === 'removed_from_repository') {
        const { repository } = body;
        if (repository) {
          try {
            const currentTeam = await models.Team.findOne({
              tenantId,
              installationId,
              accountId,
              teamId: team.node_id,
            });
            if (currentTeam) {
              const newCount =
                action === 'added_to_repository'
                  ? currentTeam.repositoriesCount + 1
                  : Math.max(0, currentTeam.repositoriesCount - 1);
              await models.Team.findOneAndUpdate(
                { tenantId, installationId, accountId, teamId: team.node_id },
                { repositoriesCount: newCount }
              );
            }
          } catch (error) {
            console.error('[Webhook] Error updating team repository count:', error.message);
          }
        }
      }

      await updateInstallationSummary(models, installationId, accountId);
      return res.status(200).json({ status: 'ok' });
    }

    // --- Membership Events ---
    if (event === 'membership') {
      const { action, member, team, organization, installation } = body;
      if (!member || !team || !organization || !installation) {
        return next(createError(400, 'Invalid payload: missing member, team, organization, or installation'));
      }

      const installationId = installation.id;
      const accountId = organization.id;
      const teamId = team.node_id;

      const route = await resolveTenantByInstallation(installationId);
      if (!route) {
        return res.status(200).json(
          await handleUnlinkedInstallation({
            event,
            installationId,
            deliveryId,
            action,
            accountLogin: organization.login,
          })
        );
      }
      const { tenantId, models } = route;

      if (action === 'added') {
        try {
          await models.TeamMember.findOneAndUpdate(
            { tenantId, installationId, teamId, userId: member.node_id },
            {
              tenantId,
              installationId,
              accountId,
              teamId,
              userId: member.node_id,
              login: member.login,
              name: member.name || null,
              email: member.email || null,
              role: body.role || 'MEMBER',
              avatarUrl: member.avatar_url || null,
            },
            { upsert: true, new: true }
          );
          const memberCount = await models.TeamMember.countDocuments({ tenantId, installationId, teamId });
          await models.Team.findOneAndUpdate(
            { tenantId, installationId, accountId, teamId },
            { memberCount }
          );
        } catch (error) {
          console.error(`[Webhook] Error adding member ${member.login} to team:`, error.message);
        }
      }

      if (action === 'removed') {
        try {
          await models.TeamMember.deleteOne({ tenantId, installationId, teamId, userId: member.node_id });
          const memberCount = await models.TeamMember.countDocuments({ tenantId, installationId, teamId });
          await models.Team.findOneAndUpdate(
            { tenantId, installationId, accountId, teamId },
            { memberCount }
          );
        } catch (error) {
          console.error(`[Webhook] Error removing member ${member.login} from team:`, error.message);
        }
      }

      await updateInstallationSummary(models, installationId, accountId);
      return res.status(200).json({ status: 'ok' });
    }

    console.log(`Event ignored: ${event}`);
    return res.status(200).json({ status: 'event ignored' });
  } catch (err) {
    next(createError(500, `Webhook processing failed: ${err.message}`));
  }
}

module.exports = {
  handleWebhook,
  resolveInstallationRepos,
  reconcileInstallationRepos,
  resolveTenantByInstallation,
  handleUnlinkedInstallation,
  handlePendingInstallationLink,
  triggerIncrementalRefresh,
  updateInstallationSummary,
};
