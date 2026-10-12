/**
 * Repository branch fetching.
 *
 * Lives here rather than in jobs/fetchInstallationSummary.js because the webhook
 * controller needs it too (push events refresh a repo's branches), and importing
 * the job would drag the whole job graph — queues, license limits, the GHAPP
 * client — into the controller's import chain.
 */
const { fetchGraphQL, BRANCHES_QUERY, sleep } = require('./githubHelpers');

// Number of days after which a branch is considered stale.
const BRANCH_STALE_DAYS = 7;

function isBranchRecentlyUpdated(committedDate, daysThreshold = BRANCH_STALE_DAYS) {
  if (!committedDate) return false;
  const cutoff = new Date();
  cutoff.setDate(cutoff.getDate() - daysThreshold);
  return new Date(committedDate) >= cutoff;
}

/**
 * Fetch a repository's branches, keeping the default branch plus anything updated
 * within BRANCH_STALE_DAYS.
 *
 * @param {boolean} throwOnError  rethrow instead of returning an empty result —
 *   callers that write the result somewhere need to tell "no branches" apart from
 *   "the fetch failed", or they persist an empty list over good data.
 */
async function fetchRepositoryBranches(token, owner, name, isArchived = false, throwOnError = false) {
  if (isArchived) {
    console.log(`[BranchFetch] Skipping branch fetch for archived repository ${owner}/${name}`);
    return { branches: [], staleBranchCount: 0 };
  }

  let branches = [];
  let after = null;
  let hasNext = true;
  let defaultBranchName = null;

  try {
    while (hasNext) {
      const data = await fetchGraphQL(token, BRANCHES_QUERY, { owner, name, after });

      if (!data.repository) {
        console.warn(`[BranchFetch] Repository ${owner}/${name} not accessible or not found`);
        return { branches: [], staleBranchCount: 0 };
      }

      if (!defaultBranchName && data.repository?.defaultBranchRef) {
        defaultBranchName = data.repository.defaultBranchRef.name;
      }

      const refs = data.repository?.refs;
      if (refs?.nodes?.length) {
        branches.push(...refs.nodes);
      }

      hasNext = refs?.pageInfo?.hasNextPage || false;
      after = refs?.pageInfo?.endCursor || null;

      await sleep(100);
    }

    const filteredBranches = branches.filter((branch) => {
      const isDefault = branch.name === defaultBranchName;
      const isRecent = isBranchRecentlyUpdated(branch.target?.committedDate);
      return isDefault || isRecent;
    });

    const staleBranchCount = branches.length - filteredBranches.length;

    console.log(
      `[BranchFetch] ${owner}/${name}: Filtered ${branches.length} branches to ${filteredBranches.length} (recent or default), ${staleBranchCount} stale`
    );

    return {
      branches: filteredBranches.map((branch) => ({
        name: branch.name,
        target: branch.target
          ? {
              oid: branch.target.oid,
              committedDate: branch.target.committedDate,
              message: branch.target.message,
              author: branch.target.author,
            }
          : null,
        isDefault: branch.name === defaultBranchName,
      })),
      staleBranchCount,
    };
  } catch (error) {
    console.error(`[BranchFetch] Error fetching branches for ${owner}/${name}:`, error.message);
    if (throwOnError) throw error;
    if (error.response?.status === 401) {
      console.error(
        `[BranchFetch] 401 Unauthorized - Check if the installation has access to ${owner}/${name}`
      );
    }
    return { branches: [], staleBranchCount: 0 };
  }
}

module.exports = { BRANCH_STALE_DAYS, isBranchRecentlyUpdated, fetchRepositoryBranches };
