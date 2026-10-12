const { getTenantModels } = require('../db/tenantModels');
const { getInstallationToken } = require('../helpers/githubTokenHelper');
const {
  fetchGraphQL,
  fetchIncrementalUserRepos,
  fetchIncrementalOrgRepos,
  fetchOrganizationTeams,
  searchRepositoriesREST,
  REPO_QUERY,
  USER_REPOS_QUERY,
  ORG_REPOS_QUERY,
  LANG_QUERY,
  CONFIG,
  sleep,
} = require('../helpers/githubHelpers');
const { runWithConcurrencyLimit } = require('../helpers/concurrencyHelper');
const { reportProgress } = require('../services/summaryRuns');
const { fetchRepositoryBranches } = require('../helpers/branchFetch');
const {
  syncOrganizationAuditSignals,
  getSecuritySignalTotals,
} = require('../helpers/securitySignalsHelper');
const { ghappRequest } = require('../helpers/ghappClient');
const {
  resolveTenantLimits,
  capReposToLimit,
  assertScanCapacity,
  recordScanTriggered,
  syncUsageMetrics,
} = require('../services/licenseLimits');


/**
 * `owner/name` for a GraphQL repository node, in the same lowercase form the
 * selection allowlist and the repo catalog use.
 */
function repoFullName(node) {
  return String(node?.url || '')
    .replace('https://github.com/', '')
    .toLowerCase();
}

/**
 * Resolve the tenant models a job needs, refusing a job that is not ours.
 *
 * CALL THIS FROM INSIDE THE try BLOCK. `getTenantModels` throws on a missing or
 * malformed tenantId, and a throw above the try skips the catch entirely — which
 * used to leave the job document on `pending` with no worker left to move it, so
 * the overview page polled a job that had already been dead for ten minutes.
 *
 * A job with no tenantId cannot be attributed to any tenant, so there is no
 * database to record its outcome against. Refusing it loudly beats guessing.
 */
function resolveJobModels(job) {
  const { tenantId } = job.data || {};
  if (!tenantId) {
    throw new Error(`Job ${job.id} carries no tenantId — refusing to process it`);
  }
  return getTenantModels(tenantId);
}

/**
 * Best-effort diagnostic log line on the BullMQ job.
 *
 * Never throws: the terminal status write in workers/summaryWorker.js is what
 * actually releases the polling UI, and a Redis hiccup writing a log line must
 * not take the real error down with it.
 */
async function logJobError(job, err) {
  try {
    await job.log(`Error: ${err.message}`);
  } catch (logErr) {
    console.error(`[SummaryJob] Could not write job log: ${logErr.message}`);
  }
}

async function triggerAutoScansForRepositories(models, installationId, accountId, login, tenantId, job) {
  try {
    // Opt-in per tenant, off by default. This is the one path that turns a
    // single "refresh my installation" into a scan of every repository, so it
    // stays dormant until an admin asks for it (see tenantSettingsSchema).
    const settings = await models.TenantSettings.findOne({ tenantId })
      .select('automation.autoScanOnSync')
      .lean();

    if (!settings?.automation?.autoScanOnSync) {
      await job?.log('Automatic scans are disabled for this organization — skipping.');
      return;
    }

    const repositories = await models.RepositoryData.find({ tenantId, installationId, accountId });

    if (repositories.length === 0) {
      return;
    }

    await job?.log(`Triggering automatic scans for ${repositories.length} repositories...`);
    let scansTriggered = 0;
    let scansFailed = 0;
    let stoppedForLicense = false;

    await runWithConcurrencyLimit(repositories, 5, async (repo) => {
      try {
        if (stoppedForLicense || repo.isArchived) {
          return;
        }

        let defaultBranch = 'main';
        
        if (repo.branches && repo.branches.length > 0) {
          const defaultBranchObj = repo.branches.find(b => b.isDefault === true);
          if (defaultBranchObj) {
            defaultBranch = defaultBranchObj.name;
          } else {
            const mainBranch = repo.branches.find(b => b.name === 'main' || b.name === 'master');
            if (mainBranch) {
              defaultBranch = mainBranch.name;
            } else {
              defaultBranch = repo.branches[0].name;
            }
          }
        }

        try {
          await assertScanCapacity(tenantId);
        } catch (limitErr) {
          if (limitErr.code === 'LICENSE_LIMIT_EXCEEDED') {
            stoppedForLicense = true;
            console.warn(
              `[AutoScan] Stopping auto-scans for tenant ${tenantId}: ${limitErr.message}`
            );
            return;
          }
          throw limitErr;
        }

        const scanPayload = {
          installation_id: String(installationId),
          org_name: repo.owner,
          repo_name: repo.repositoryName,
          branch: defaultBranch,
          scan_type: 'all'
        };

        await ghappRequest('POST', '/scan', {
          data: scanPayload,
          timeout: 10000,
        });
        await recordScanTriggered(tenantId);
        scansTriggered++;

        await sleep(500);
      } catch (error) {
        scansFailed++;
      }
    });

    await job?.log(
      `Automatic scans triggered: ${scansTriggered} started, ${scansFailed} failed` +
        (stoppedForLicense ? ' (stopped early: plan scan limit reached)' : '')
    );
  } catch (error) {
    // Don't throw - this is a non-critical operation that shouldn't fail the main job
  }
}

async function fetchAndSaveTeamsData(models, token, installationId, accountId, login, job, tenantId) {
  const { Team, TeamMember } = models;
  try {
    console.log(`[TeamsData] Starting teams data fetch for organization ${login}`);
    await job.log(`Fetching teams data for organization ${login}...`);

    const teamsWithMembers = await fetchOrganizationTeams(token, login);

    if (teamsWithMembers.length === 0) {
      console.log(`[TeamsData] No teams data available for organization ${login}`);
      await job.log('Teams data not available (check GitHub App permissions: requires "Members" read access)');
      return { teamsCount: 0, membersCount: 0 };
    }

    let totalMembers = 0;

    // Save each team and its members
    for (const teamData of teamsWithMembers) {
      try {
        // Save team
        const team = await Team.findOneAndUpdate(
          {
            tenantId,
            installationId,
            accountId,
            teamId: teamData.id
          },
          {
            tenantId,
            installationId,
            accountId,
            login,
            teamId: teamData.id,
            teamName: teamData.name,
            teamSlug: teamData.slug,
            description: teamData.description || null,
            privacy: teamData.privacy,
            memberCount: teamData.members?.totalCount || 0,
            repositoriesCount: teamData.repositories?.totalCount || 0,
          },
          { upsert: true, new: true }
        );

        console.log(`[TeamsData] Saved team: ${teamData.name} (${teamData.slug}) with ${teamData.membersData?.length || 0} members`);

        // Save team members
        if (teamData.membersData && teamData.membersData.length > 0) {
          for (const memberEdge of teamData.membersData) {
            try {
              const member = memberEdge.node;
              const role = memberEdge.role;

              await TeamMember.findOneAndUpdate(
                {
                  tenantId,
                  installationId,
                  teamId: teamData.id,
                  userId: member.id
                },
                {
                  tenantId,
                  installationId,
                  accountId,
                  teamId: teamData.id,
                  userId: member.id,
                  login: member.login,
                  name: member.name || null,
                  email: member.email || null,
                  role: role,
                  avatarUrl: member.avatarUrl || null,
                },
                { upsert: true, new: true }
              );

              totalMembers++;
            } catch (memberError) {
              console.warn(`[TeamsData] Error saving member ${memberEdge.node?.login}:`, memberError.message);
            }
          }
        }
      } catch (teamError) {
        console.warn(`[TeamsData] Error saving team ${teamData.name}:`, teamError.message);
      }
    }

    console.log(`[TeamsData] Completed teams data fetch. Saved ${teamsWithMembers.length} teams and ${totalMembers} total members`);
    await job.log(`Saved ${teamsWithMembers.length} teams and ${totalMembers} team members`);

    return { teamsCount: teamsWithMembers.length, membersCount: totalMembers };
  } catch (error) {
    console.error(`[TeamsData] Error fetching teams data:`, error.message);
    const errorHint = error.message?.includes('FORBIDDEN') || error.message?.includes('Resource not accessible')
      ? 'GitHub App lacks "Members" organization permission'
      : error.message;
    await job.log(`Info: Teams data unavailable - ${errorHint}`);
    // Don't throw - teams data is supplementary, don't fail the whole job
    return { teamsCount: 0, membersCount: 0 };
  }
}

/**
 * Process incremental installation summary - fetches only updated repositories
 */
async function processIncrementalInstallationSummary(job) {
  const { installationId, accountId, login, accountType, mongoJobId, tenantId } = job.data;

  try {
    const models = resolveJobModels(job);
    const { InstallationSummaryJob, Installation, RepositoryData, Team, TeamMember, GitHubSecurityEvent } = models;

    console.log(`[IncrementalSummary] Starting incremental fetch for installation ${installationId}`);
    await job.updateProgress(0);
    await job.log('Starting incremental installation summary fetch...');

    const token = await getInstallationToken(installationId);
    
    // Status only: progress was reset by whoever queued this run. Resetting it
    // here again dragged the bar back to 0 on every BullMQ retry.
    await InstallationSummaryJob.findByIdAndUpdate(mongoJobId, {
      status: 'in_progress',
    });

    // Get lastFetchedAt timestamp
    const installation = await Installation.findOne({ installationId });
    const lastFetchedAt = installation?.lastFetchedAt;

    if (accountType === 'Organization') {
      try {
        await job.log('Syncing PAT/fork security signals from organization audit log...');
        const auditResult = await syncOrganizationAuditSignals(GitHubSecurityEvent, {
          token,
          installationId,
          accountId,
          login,
          since: lastFetchedAt,
          tenantId,
        });

        await job.log(
          `Audit sync result: inserted=${auditResult.inserted || 0}, skipped=${Boolean(auditResult.skipped)}, reason=${auditResult.reason || 'none'}`
        );
      } catch (auditError) {
        console.warn(`[IncrementalSummary] Audit sync skipped: ${auditError.message}`);
        await job.log(`Info: Audit sync skipped - ${auditError.message}`);
      }
    }

    console.log(`[IncrementalSummary] Installation found:`, { installationId, lastFetchedAt });

    if (!lastFetchedAt) {
      console.log(`[IncrementalSummary] No lastFetchedAt found, falling back to full fetch`);
      await job.log('No lastFetchedAt found, falling back to full fetch...');
      return processInstallationSummary(job);
    }

    console.log(`[IncrementalSummary] Incremental fetch: repositories updated after ${lastFetchedAt.toISOString()}`);
    await job.log(`Incremental fetch: repositories updated after ${lastFetchedAt.toISOString()}`);

    // Determine if this is an organization or user installation
    const isOrganization = accountType === 'Organization';

    // Fetch repositories using GraphQL with incremental logic
    // This will fetch repos in batches of 10 and stop when updatedAt <= lastFetchedAt
    let repos = [];
    
    console.log(`[IncrementalSummary] Using GraphQL incremental fetch for ${isOrganization ? 'organization' : 'user'}: ${login}`);
    await job.log(`Fetching updated repositories using GraphQL (10 per batch)...`);

    if (isOrganization) {
      repos = await fetchIncrementalOrgRepos(token, login, lastFetchedAt, CONFIG.INCREMENTAL_PAGE_SIZE);
    } else {
      repos = await fetchIncrementalUserRepos(token, login, lastFetchedAt, CONFIG.INCREMENTAL_PAGE_SIZE);
    }

    const limits = await resolveTenantLimits(tenantId);
    const maxRepos = limits.maxRepos;
    await job.log(
      `License plan=${limits.planId || 'none'} maxRepos=${maxRepos} (active=${limits.active})`
    );

    console.log(`[IncrementalSummary] Found ${repos.length} updated repositories`);
    await job.log(`Found ${repos.length} updated repositories (including archived repos)`);

    // Update initial progress
    await reportProgress(job, InstallationSummaryJob, mongoJobId, 40);

    // If no repos found, just update summary from existing data
    if (repos.length === 0) {
      console.log(`[IncrementalSummary] No updated repositories found. Recalculating summary from existing data...`);
      await job.log('No updated repositories found. Recalculating summary from existing data...');

      const allReposData = await RepositoryData.find({ tenantId, installationId, accountId });

      const totalBranches = allReposData.reduce((s, r) => s + (r.branches?.length || 0) + (r.staleBranchCount || 0), 0);
      const totalCommits = allReposData.reduce((s, r) => s + (r.totalCommits || 0), 0);
      const totalForks = allReposData.reduce((s, r) => s + (r.forks || 0), 0);
      const totalStars = allReposData.reduce((s, r) => s + (r.stars || 0), 0);
      const totalPrivate = allReposData.filter(r => r.isPrivate).length;
      const totalPublic = allReposData.length - totalPrivate;
      const totalInternal = allReposData.filter(r => r.isInternal).length;
      const totalArchivedRepos = allReposData.filter(r => r.isArchived).length;
      const totalStaleBranches = allReposData.reduce((s, r) => s + (r.staleBranchCount || 0), 0);

      const existingJob = await InstallationSummaryJob.findById(mongoJobId);
      const languages = existingJob?.summary?.languages || [];
      const totalBytes = existingJob?.summary?.totals?.totalBytes || 0;

      const repositories = allReposData
        .map((r) => ({
          name: r.repositoryName,
          url: r.repositoryUrl,
          stars: r.stars || 0,
          forks: r.forks || 0,
          isPrivate: r.isPrivate || false,
          branches: r.branches?.length || 0,
          commits: r.totalCommits || 0,
          lastCommit: r.branches?.[0]?.target?.committedDate || null,
          lastActive: r.lastActive,
        }))
        .sort((a, b) => new Date(b.lastActive) - new Date(a.lastActive));

      const summary = {
        totals: {
          totalRepositories: allReposData.length,
          totalBranches,
          totalCommits,
          totalForks,
          totalStars,
          totalPrivate,
          totalPublic,
          totalInternal,
          totalBytes,
          totalArchivedRepos,
          totalStaleBranches,
          totalTeams: 0,
          totalTeamMembers: 0,
          totalSecurityEvents: 0,
          totalPatNoExpiry: 0,
          totalPatExpired: 0,
          totalPatOverPermissive: 0,
          totalExternalForks: 0,
        },
        languages,
        repositories,
        teams: [],
      };

      const securityTotals = await getSecuritySignalTotals(GitHubSecurityEvent, installationId, accountId, tenantId);
      summary.totals.totalSecurityEvents = securityTotals.totalSecurityEvents;
      summary.totals.totalPatNoExpiry = securityTotals.totalPatNoExpiry;
      summary.totals.totalPatExpired = securityTotals.totalPatExpired;
      summary.totals.totalPatOverPermissive = securityTotals.totalPatOverPermissive;
      summary.totals.totalExternalForks = securityTotals.totalExternalForks;

      await InstallationSummaryJob.findByIdAndUpdate(mongoJobId, {
        summary,
        progress: 95,
        status: 'in_progress',
        updatedAt: new Date(),
      });

      // Fetch teams data for organization installations
      if (isOrganization) {
        await job.log('Fetching teams data for organization...');
        await fetchAndSaveTeamsData(models, token, installationId, accountId, login, job, tenantId);
        
        // Now fetch teams from DB after they've been saved
        const allTeams = await Team.find({ tenantId, installationId, accountId });
        const totalTeams = allTeams.length;
        const totalTeamMembers = await TeamMember.countDocuments({ tenantId, installationId, accountId });

        const teamsData = allTeams.map(team => ({
          teamId: team.teamId,
          teamName: team.teamName,
          teamSlug: team.teamSlug,
          memberCount: team.memberCount,
          repositoriesCount: team.repositoriesCount,
        }));

        // Update summary with teams data
        summary.totals.totalTeams = totalTeams;
        summary.totals.totalTeamMembers = totalTeamMembers;
        summary.teams = teamsData;

        console.log(`[IncrementalSummary] Updated summary with ${totalTeams} teams and ${totalTeamMembers} members`);
      }

      // Final update with teams data
      await InstallationSummaryJob.findByIdAndUpdate(mongoJobId, {
        summary,
        progress: 100,
        status: 'completed',
        updatedAt: new Date(),
      });

      await Installation.findOneAndUpdate(
        { installationId },
        { lastFetchedAt: new Date() }
      );

      await job.updateProgress(100);
      await job.log('Summary completed successfully (no updates)');

      await syncUsageMetrics(tenantId);

      // Opt-in per tenant; no-ops unless automation.autoScanOnSync is enabled.
      await triggerAutoScansForRepositories(models, installationId, accountId, login, tenantId, job);

      return { success: true, summary };
    }

    // Fetch languages for updated repos
    await job.log(`Fetching languages for ${repos.length} updated repos...`);
    const langMap = new Map();
    let done = 0;

    await runWithConcurrencyLimit(repos, 6, async (repo) => {
      try {
        const [owner, name] = repo.url.replace('https://github.com/', '').split('/');
        const data = await fetchGraphQL(token, LANG_QUERY, { owner, name });

        (data.repository?.languages?.edges || []).forEach((edge) => {
          const lang = edge.node.name;
          const existing = langMap.get(lang) || { bytes: 0, count: 0, color: edge.node.color };
          langMap.set(lang, {
            bytes: existing.bytes + edge.size,
            count: existing.count + 1,
            color: existing.color,
          });
        });
      } catch {
      } finally {
        done++;
        const progress = 40 + Math.floor((done / repos.length) * 30);
        await reportProgress(job, InstallationSummaryJob, mongoJobId, progress);
      }
    });

    // Fetch branches and save to database
    await job.log('Fetching branches and saving updated repositories to database...');
    let reposDone = 0;
    let skippedForLimit = 0;

    await runWithConcurrencyLimit(repos, 3, async (repo) => {
      try {
        const [owner, name] = repo.url.replace('https://github.com/', '').split('/');
        const isArchived = repo.isArchived || false;

        const existing = await RepositoryData.findOne({
          tenantId,
          installationId,
          accountId,
          repositoryName: name,
        }).select('_id');

        if (!existing) {
          const currentCount = await RepositoryData.countDocuments({ tenantId });
          if (!limits.active || currentCount >= maxRepos) {
            skippedForLimit++;
            console.warn(
              `[IncrementalSummary] Skipping new repo ${owner}/${name}: license maxRepos=${maxRepos}`
            );
            return;
          }
        }

        const { branches, staleBranchCount } = await fetchRepositoryBranches(token, owner, name, isArchived);

        const repoData = {
          tenantId,
          installationId,
          accountId,
          login,
          repositoryName: name,
          repositoryUrl: repo.url,
          owner,
          isPrivate: repo.isPrivate || false,
          isArchived,
          isInternal: repo.visibility === 'INTERNAL',
          stars: repo.stargazerCount || 0,
          forks: repo.forkCount || 0,
          branches,
          staleBranchCount,
          totalCommits: repo.refs?.nodes?.[0]?.target?.history?.totalCount || 0,
          lastActive: repo.updatedAt,
        };

        await RepositoryData.findOneAndUpdate(
          { tenantId, installationId, accountId, repositoryName: name },
          repoData,
          { upsert: true, new: true }
        );

        console.log(`[IncrementalSummary] Updated ${branches.length} branches for ${owner}/${name}${isArchived ? ' (archived)' : ''}, ${staleBranchCount} stale branches`);
      } catch (error) {
        console.error(`[IncrementalSummary] Error saving repo data:`, error.message);
      } finally {
        reposDone++;
        const progress = 70 + Math.floor((reposDone / repos.length) * 25);
        await reportProgress(job, InstallationSummaryJob, mongoJobId, progress);
      }
    });

    if (skippedForLimit > 0) {
      await job.log(
        `Skipped ${skippedForLimit} new repositories due to license maxRepos=${maxRepos}`
      );
    }

    // Note: Deletion detection is handled by webhook events (repository_removed)
    // The incremental worker only processes updates, not deletions
    console.log(`[IncrementalSummary] Skipping deletion check - handled by webhooks`);

    // Aggregate final summary from ALL repositories (not just updated ones)
    await job.log('Aggregating final summary from all repositories...');

    const allReposData = await RepositoryData.find({ tenantId, installationId, accountId });

    const totalBranches = allReposData.reduce((s, r) => s + (r.branches?.length || 0) + (r.staleBranchCount || 0), 0);
    const totalCommits = allReposData.reduce((s, r) => s + (r.totalCommits || 0), 0);
    const totalForks = allReposData.reduce((s, r) => s + (r.forks || 0), 0);
    const totalStars = allReposData.reduce((s, r) => s + (r.stars || 0), 0);
    const totalPrivate = allReposData.filter(r => r.isPrivate).length;
    const totalPublic = allReposData.length - totalPrivate;
    const totalInternal = allReposData.filter(r => r.isInternal).length;
    const totalArchivedRepos = allReposData.filter(r => r.isArchived).length;
    const totalStaleBranches = allReposData.reduce((s, r) => s + (r.staleBranchCount || 0), 0);

    // Merge language data (existing + new)
    const existingJob = await InstallationSummaryJob.findById(mongoJobId);
    const existingLanguages = existingJob?.summary?.languages || [];

    // Create a map from existing languages
    const mergedLangMap = new Map();
    existingLanguages.forEach(lang => {
      mergedLangMap.set(lang.name, {
        bytes: lang.bytes,
        count: lang.repo_count,
        color: lang.color,
      });
    });

    // Merge with new language data
    for (const [name, data] of langMap.entries()) {
      const existing = mergedLangMap.get(name) || { bytes: 0, count: 0, color: data.color };
      mergedLangMap.set(name, {
        bytes: existing.bytes + data.bytes,
        count: existing.count + data.count,
        color: data.color,
      });
    }

    const totalBytes = [...mergedLangMap.values()].reduce((a, v) => a + v.bytes, 0);

    const languages = [...mergedLangMap.entries()]
      .map(([name, d]) => ({
        name,
        bytes: d.bytes,
        repo_count: d.count,
        percentage: totalBytes ? +((d.bytes / totalBytes) * 100).toFixed(1) : 0,
        color: d.color,
      }))
      .sort((a, b) => b.bytes - a.bytes);

    const repositories = allReposData
      .map((r) => ({
        name: r.repositoryName,
        url: r.repositoryUrl,
        stars: r.stars || 0,
        forks: r.forks || 0,
        isPrivate: r.isPrivate || false,
        branches: r.branches?.length || 0,
        commits: r.totalCommits || 0,
        lastCommit: r.branches?.[0]?.target?.committedDate || null,
        lastActive: r.lastActive,
      }))
      .sort((a, b) => new Date(b.lastActive) - new Date(a.lastActive));

    // Update lastFetchedAt timestamp
    await Installation.findOneAndUpdate(
      { installationId },
      { lastFetchedAt: new Date() }
    );
    await job.log('Updated lastFetchedAt timestamp');

    const summary = {
      totals: {
        totalRepositories: allReposData.length,
        totalBranches,
        totalCommits,
        totalForks,
        totalStars,
        totalPrivate,
        totalInternal,
        totalPublic,
        totalBytes,
        totalArchivedRepos,
        totalStaleBranches,
        totalTeams: 0,
        totalTeamMembers: 0,
        totalSecurityEvents: 0,
        totalPatNoExpiry: 0,
        totalPatExpired: 0,
        totalPatOverPermissive: 0,
        totalExternalForks: 0,
      },
      languages,
      repositories,
      teams: [],
    };

    const securityTotals = await getSecuritySignalTotals(GitHubSecurityEvent, installationId, accountId, tenantId);
    summary.totals.totalSecurityEvents = securityTotals.totalSecurityEvents;
    summary.totals.totalPatNoExpiry = securityTotals.totalPatNoExpiry;
    summary.totals.totalPatExpired = securityTotals.totalPatExpired;
    summary.totals.totalPatOverPermissive = securityTotals.totalPatOverPermissive;
    summary.totals.totalExternalForks = securityTotals.totalExternalForks;

    await InstallationSummaryJob.findByIdAndUpdate(mongoJobId, {
      summary,
      progress: 95,
      status: 'in_progress',
      updatedAt: new Date(),
    });

    // Fetch teams data for organization installations
    if (isOrganization) {
      await job.log('Fetching teams data for organization...');
      await fetchAndSaveTeamsData(models, token, installationId, accountId, login, job, tenantId);
      
      // Now fetch teams from DB after they've been saved
      const allTeams = await Team.find({ tenantId, installationId, accountId });
      const totalTeams = allTeams.length;
      const totalTeamMembers = await TeamMember.countDocuments({ tenantId, installationId, accountId });

      const teamsData = allTeams.map(team => ({
        teamId: team.teamId,
        teamName: team.teamName,
        teamSlug: team.teamSlug,
        memberCount: team.memberCount,
        repositoriesCount: team.repositoriesCount,
      }));

      // Update summary with teams data
      summary.totals.totalTeams = totalTeams;
      summary.totals.totalTeamMembers = totalTeamMembers;
      summary.teams = teamsData;

      console.log(`[IncrementalSummary] Updated summary with ${totalTeams} teams and ${totalTeamMembers} members`);
    }

    // Final update with teams data
    await InstallationSummaryJob.findByIdAndUpdate(mongoJobId, {
      summary,
      progress: 100,
      status: 'completed',
      updatedAt: new Date(),
    });

    await job.updateProgress(100);
    console.log(`[IncrementalSummary] Completed successfully. Updated ${repos.length} repositories.`);
    await job.log(`Incremental summary completed successfully. Updated ${repos.length} repositories.`);

    await syncUsageMetrics(tenantId);

    // Opt-in per tenant; no-ops unless automation.autoScanOnSync is enabled.
    await triggerAutoScansForRepositories(models, installationId, accountId, login, tenantId, job);

    return { success: true, summary };
  } catch (err) {
    // The `failed` status write lives in workers/summaryWorker.js so that it also
    // covers throws that never reach this catch, and so that it fires only once
    // BullMQ has exhausted its retries rather than after every attempt.
    console.error('[IncrementalSummary] Failed:', err.message);
    await logJobError(job, err);
    throw err;
  }
}

async function processInstallationSummary(job) {
  const { installationId, accountId, login, accountType, mongoJobId, tenantId } = job.data;
  // accountId is organization id for org installations and user id for individual installations
  // login is the login/username of the account
  // accountType is 'Organization' or 'User'

  try {
    const models = resolveJobModels(job);
    const { InstallationSummaryJob, Installation, RepositoryData, Team, TeamMember, GitHubSecurityEvent } = models;

    await job.updateProgress(0);
    await job.log('Starting installation summary fetch...');

    const token = await getInstallationToken(installationId);
    const installation = await Installation.findOne({ installationId });

    if (accountType === 'Organization') {
      try {
        await job.log('Syncing PAT/fork security signals from organization audit log...');
        const auditResult = await syncOrganizationAuditSignals(GitHubSecurityEvent, {
          token,
          installationId,
          accountId,
          login,
          since: installation?.lastFetchedAt,
          tenantId,
        });
        await job.log(
          `Audit sync result: inserted=${auditResult.inserted || 0}, skipped=${Boolean(auditResult.skipped)}, reason=${auditResult.reason || 'none'}`
        );
      } catch (auditError) {
        console.warn(`[SummaryJob] Audit sync skipped: ${auditError.message}`);
        await job.log(`Info: Audit sync skipped - ${auditError.message}`);
      }
    }

    let repos = [];
    let after = null;
    let hasNext = true;

    // Status only: progress was reset by whoever queued this run. Resetting it
    // here again dragged the bar back to 0 on every BullMQ retry.
    await InstallationSummaryJob.findByIdAndUpdate(mongoJobId, {
      status: 'in_progress',
    });

    // Determine if this is an organization or user installation
    const isOrganization = accountType === 'Organization';
    const reposQuery = isOrganization ? ORG_REPOS_QUERY : USER_REPOS_QUERY;

    const limits = await resolveTenantLimits(tenantId);
    const maxRepos = limits.maxRepos;
    await job.log(
      `License plan=${limits.planId || 'none'} maxRepos=${maxRepos} (active=${limits.active})`
    );
    if (!limits.active || maxRepos <= 0) {
      throw new Error(
        `Cannot sync repositories: license inactive or maxRepos=${maxRepos} for plan ${limits.planId || 'none'}`
      );
    }
    
    // An installation larger than the plan allows has an explicit allowlist (the
    // repositories the admin chose in the chooser). Honour it instead of taking
    // whichever repositories happen to sort first — those are two very different
    // answers to "which 2,000 of your 21,000 repos do we watch".
    const allowlist = new Set(installation?.selectedRepos || []);
    const hasAllowlist = allowlist.size > 0;
    const targetCount = hasAllowlist ? Math.min(allowlist.size, maxRepos) : maxRepos;
    if (hasAllowlist) {
      await job.log(`Restricting to the ${allowlist.size} repositories selected for this installation`);
    }

    await job.log(`Fetching repositories for ${isOrganization ? 'organization' : 'user'}: ${login}...`);
    
    while (hasNext) {
      const data = await fetchGraphQL(token, reposQuery, {
        login,
        after,
        pageSize: CONFIG.PAGE_SIZE || 50,
      });

      // Extract repositories based on account type
      const repoData = isOrganization 
        ? data.organization?.repositories 
        : data.user?.repositories;
      
      const nodes = repoData?.nodes || [];
      const wanted = hasAllowlist
        ? nodes.filter((node) => allowlist.has(repoFullName(node)))
        : nodes;
      if (wanted.length) repos.push(...wanted);

      hasNext = repoData?.pageInfo?.hasNextPage || false;
      after = repoData?.pageInfo?.endCursor || null;

      // Measured against how many repositories this walk will actually yield.
      // It was measured against the plan ceiling alone, so a 30-repo org on a
      // 2,000-repo plan sat at 0% for the whole discovery and then leapt to 40%.
      const expected = hasAllowlist
        ? targetCount
        : Math.min(targetCount, Number(repoData?.totalCount) || targetCount);
      const progress = Math.min(
        Math.floor((repos.length / Math.max(expected, 1)) * 40),
        40
      );

      await reportProgress(job, InstallationSummaryJob, mongoJobId, progress);
      await sleep(200);

      // With an allowlist the walk ends once every selected repository has been
      // seen; without one it ends at the plan ceiling.
      if (repos.length >= targetCount) break;
    }

    repos = capReposToLimit(repos, maxRepos);
    await job.log(
      `Processing ${repos.length} repositories (license maxRepos=${maxRepos}` +
        `${hasAllowlist ? `, selected=${allowlist.size}` : ''})`
    );

    await job.log(`Fetching languages for ${repos.length} repos...`);
    const langMap = new Map();
    let done = 0;

    await runWithConcurrencyLimit(repos, 6, async (repo) => {
      try {
        const [owner, name] = repo.url.replace('https://github.com/', '').split('/');
        const data = await fetchGraphQL(token, LANG_QUERY, { owner, name });

        (data.repository?.languages?.edges || []).forEach((edge) => {
          const lang = edge.node.name;
          const existing =
            langMap.get(lang) || { bytes: 0, count: 0, color: edge.node.color };
          langMap.set(lang, {
            bytes: existing.bytes + edge.size,
            count: existing.count + 1,
            color: existing.color,
          });
        });
      } catch {
      } finally {
        done++;
        const progress = 40 + Math.floor((done / repos.length) * 30);
        await reportProgress(job, InstallationSummaryJob, mongoJobId, progress);
      }
    });

    await job.log('Fetching branches and saving to database...');
    let reposDone = 0;

    await runWithConcurrencyLimit(repos, 3, async (repo) => {
      try {
        const [owner, name] = repo.url.replace('https://github.com/', '').split('/');
        const isArchived = repo.isArchived || false;
        
        if (isArchived) {
          console.log(`[SummaryJob] Processing archived repo: ${owner}/${name}`);
        }
        
        const { branches, staleBranchCount } = await fetchRepositoryBranches(token, owner, name, isArchived);

        const repoData = {
          tenantId,
          installationId,
          accountId,
          login,
          repositoryName: name,
          repositoryUrl: repo.url,
          owner,
          isPrivate: repo.isPrivate || false,
          isArchived,
          isInternal: repo.visibility === 'INTERNAL',
          stars: repo.stargazerCount || 0,
          forks: repo.forkCount || 0,
          branches,
          staleBranchCount,
          totalCommits: repo.refs?.nodes?.[0]?.target?.history?.totalCount || 0,
          lastActive: repo.updatedAt,
        };

        const savedRepo = await RepositoryData.findOneAndUpdate(
          { tenantId, installationId, accountId, repositoryName: name },
          repoData,
          { upsert: true, new: true }
        );

        console.log(`[SummaryJob] Saved ${branches.length} branches for ${owner}/${name}${isArchived ? ' (archived)' : ''}, ${staleBranchCount} stale branches, isArchived in DB: ${savedRepo.isArchived}`);
      } catch (error) {
        console.error(`[SummaryJob] Error saving repo data:`, error.message);
      } finally {
        reposDone++;
        const progress = 70 + Math.floor((reposDone / repos.length) * 25);
        await reportProgress(job, InstallationSummaryJob, mongoJobId, progress);
      }
    });

    await job.log('Aggregating final summary...');
    
    // Fetch all saved repository data to get accurate stale branch counts and archived repos
    const allReposData = await RepositoryData.find({ tenantId, installationId, accountId });
    
    console.log(`[SummaryJob] Found ${allReposData.length} repos in MongoDB for aggregation`);
    const archivedRepos = allReposData.filter((r) => r.isArchived);
    console.log(`[SummaryJob] Archived repos:`, archivedRepos.map(r => r.repositoryName));
    
    const totalBranches = repos.reduce((s, r) => s + (r.refs?.totalCount || 0), 0);
    const totalForks = repos.reduce((s, r) => s + (r.forkCount || 0), 0);
    const totalStars = repos.reduce((s, r) => s + (r.stargazerCount || 0), 0);
    const totalCommits = repos.reduce(
      (s, r) => s + (r.refs?.nodes?.[0]?.target?.history?.totalCount || 0),
      0
    );
    const totalPrivate = repos.filter((r) => r.isPrivate).length;
    const totalPublic = repos.length - totalPrivate;
    const totalInternal = allReposData.filter((r) => r.isInternal).length;
    // Use MongoDB data for accurate archived repos count
    const totalArchivedRepos = allReposData.filter((r) => r.isArchived).length;
    const totalStaleBranches = allReposData.reduce((s, r) => s + (r.staleBranchCount || 0), 0);
    const totalBytes = [...langMap.values()].reduce((a, v) => a + v.bytes, 0);
    
    console.log(`[SummaryJob] Summary stats:`, {
      totalRepositories: repos.length,
      totalArchivedRepos,
      totalStaleBranches,
      totalBranches,
      totalPrivate,
      totalPublic,
      totalInternal,
    });

    const languages = [...langMap.entries()]
      .map(([name, d]) => ({
        name,
        bytes: d.bytes,
        repo_count: d.count,
        percentage: totalBytes ? +((d.bytes / totalBytes) * 100).toFixed(1) : 0,
        color: d.color,
      }))
      .sort((a, b) => b.bytes - a.bytes);

    const repositories = repos
      .map((r) => ({
        name: r.name,
        url: r.url,
        stars: r.stargazerCount,
        forks: r.forkCount,
        isPrivate: r.isPrivate || false,
        branches: r.refs?.totalCount || 0,
        commits: r.refs?.nodes?.[0]?.target?.history?.totalCount || 0,
        lastCommit:
          r.refs?.nodes?.[0]?.target?.history?.nodes?.[0]?.committedDate || null,
        lastActive: r.updatedAt,
      }))
      .sort((a, b) => new Date(b.lastActive) - new Date(a.lastActive));

    // Update lastFetchedAt timestamp for future incremental refreshes
    await Installation.findOneAndUpdate(
      { installationId },
      { lastFetchedAt: new Date() }
    );

   
    let totalTeams = 0;
    let totalTeamMembers = 0;
    let teams = []
    // Fetch teams data for organization installations
    if (isOrganization) {
      await job.log('Fetching teams data for organization...');
      await fetchAndSaveTeamsData(models, token, installationId, accountId, login, job, tenantId);
      
      // Now fetch teams from DB after they've been saved
      const allTeams = await Team.find({ tenantId, installationId, accountId });
      totalTeams = allTeams.length;
      totalTeamMembers = await TeamMember.countDocuments({ tenantId, installationId, accountId });

      const teamsData = allTeams.map(team => ({
        teamId: team.teamId,
        teamName: team.teamName,
        teamSlug: team.teamSlug,
        memberCount: team.memberCount,
        repositoriesCount: team.repositoriesCount,
      }));

      // Update summary with teams data
      teams = teamsData;

      console.log(`[SummaryJob] Updated summary with ${totalTeams} teams and ${totalTeamMembers} members`);
    }

     await job.log('Summary completed successfully');

    const summary = {
      totals: {
        totalRepositories: repos.length,
        totalBranches,
        totalCommits,
        totalForks,
        totalStars,
        totalPrivate,
        totalPublic,
        totalInternal,
        totalBytes,
        totalArchivedRepos,
        totalStaleBranches,
        totalTeams: totalTeams,
        totalTeamMembers: totalTeamMembers,
        totalSecurityEvents: 0,
        totalPatNoExpiry: 0,
        totalPatExpired: 0,
        totalPatOverPermissive: 0,
        totalExternalForks: 0,
      },
      languages,
      teams,
      repositories
    };

    const securityTotals = await getSecuritySignalTotals(GitHubSecurityEvent, installationId, accountId, tenantId);
    summary.totals.totalSecurityEvents = securityTotals.totalSecurityEvents;
    summary.totals.totalPatNoExpiry = securityTotals.totalPatNoExpiry;
    summary.totals.totalPatExpired = securityTotals.totalPatExpired;
    summary.totals.totalPatOverPermissive = securityTotals.totalPatOverPermissive;
    summary.totals.totalExternalForks = securityTotals.totalExternalForks;

// update with teams data
    await InstallationSummaryJob.findByIdAndUpdate(mongoJobId, {
      summary,
      progress: 100,
      status: 'completed',
      updatedAt: new Date(),
    });

    await job.updateProgress(100);

    await syncUsageMetrics(tenantId);

    // Opt-in per tenant; no-ops unless automation.autoScanOnSync is enabled.
    await triggerAutoScansForRepositories(models, installationId, accountId, login, tenantId, job);

    return { success: true, summary };
  } catch (err) {
    // See the note in processIncrementalInstallationSummary: the terminal
    // `failed` write is the worker's job, not this function's.
    console.error('[SummaryJob] Failed:', err.message);
    await logJobError(job, err);
    throw err;
  }
}

module.exports = { processInstallationSummary, processIncrementalInstallationSummary };
