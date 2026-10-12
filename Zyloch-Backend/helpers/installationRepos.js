// helpers/installationRepos.js
//
// Reading an installation's repository list from the GitHub API instead of from
// the webhook payload.
//
// A webhook payload is not a reliable inventory for a large installation: an app
// installed on "All repositories" reports `repository_selection: "all"` and the
// `repositories` array GitHub ships with it is a convenience snapshot, capped by
// the 25MB delivery ceiling, so for an org with thousands of repos it arrives
// partial or not at all. `GET /installation/repositories` is paginated and
// authoritative, and reports `total_count` even when only the first page is read.
const axios = require('axios');

const PER_PAGE = 100;
const REQUEST_TIMEOUT_MS = 60000;

function nextLinkFrom(headers) {
  return headers?.link?.match(/<([^>]+)>; rel="next"/)?.[1] || null;
}

/**
 * List the repositories an installation can access, stopping once `limit` have
 * been collected.
 *
 * `limit` is the tenant's plan cap (`license_plans.maxRepos`) and may be
 * `Infinity` for an uncapped plan — this helper never invents a ceiling of its
 * own, it only stops paging once the caller's limit is reached.
 *
 * `onPage` is called with each page as it arrives. A caller that is streaming
 * pages into storage (the repo catalog sync, which walks tens of thousands of
 * repositories) passes `collect: false` so the whole list is never held in
 * memory at once.
 *
 * @param {string} token installation access token
 * @param {{limit?: number, perPage?: number, onPage?: Function, collect?: boolean}} options
 * @returns {Promise<{repositories: Array<object>, totalCount: number, readCount: number, truncated: boolean}>}
 *   `totalCount` is GitHub's figure for the whole installation (not just what was
 *   read); `truncated` says the list was cut short by `limit`.
 */
async function fetchInstallationRepositories(
  token,
  { limit = Infinity, perPage = PER_PAGE, onPage = null, collect = true } = {}
) {
  const headers = { Authorization: `Bearer ${token}`, Accept: 'application/vnd.github+json' };
  const pageSize = Number.isFinite(limit) ? Math.min(perPage, Math.max(limit, 1)) : perPage;

  let repositories = [];
  let readCount = 0;
  let totalCount = 0;
  let nextUrl = `https://api.github.com/installation/repositories?per_page=${pageSize}`;

  while (nextUrl) {
    const response = await axios.get(nextUrl, { headers, timeout: REQUEST_TIMEOUT_MS });
    let page = response.data?.repositories || [];
    totalCount = Number(response.data?.total_count) || totalCount || readCount + page.length;

    if (Number.isFinite(limit) && readCount + page.length > limit) {
      page = page.slice(0, Math.max(limit - readCount, 0));
    }

    readCount += page.length;
    if (collect) repositories = repositories.concat(page);
    if (onPage && page.length) await onPage(page, { readCount, totalCount });

    if (Number.isFinite(limit) && readCount >= limit) break;

    nextUrl = nextLinkFrom(response.headers);
  }

  if (totalCount < readCount) totalCount = readCount;

  return {
    repositories,
    readCount,
    totalCount,
    truncated: totalCount > readCount,
  };
}

/** `owner/name`, lowercased, for the `Installation.repos` list. */
function toRepoNames(repositories) {
  return (repositories || [])
    .map((repo) => repo?.full_name)
    .filter((fullName) => typeof fullName === 'string' && fullName.length > 0)
    .map((fullName) => fullName.toLowerCase());
}

module.exports = { fetchInstallationRepositories, toRepoNames, PER_PAGE };
