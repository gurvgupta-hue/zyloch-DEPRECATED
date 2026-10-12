// helpers/githubHelpers.js
const axios = require("axios");

// --- Configuration ---
// Repo caps (formerly MAX_REPOS) come from license_plans.maxRepos via
// services/licenseLimits.js — do not hardcode plan limits here.
const CONFIG = {
  PAGE_SIZE: 50,
  TOP_N_LANG_REPOS: 50,
  BACKOFF_MS: 1000,
  MAX_BACKOFF: 60000,
  RATE_THRESHOLD: 20,
  MAX_RATE_LIMIT_WAIT_MS: 2 * 60 * 1000, // don't block a job/worker slot longer than this waiting on GitHub's rate limit reset
  INCREMENTAL_PAGE_SIZE: 10, // Smaller page size for incremental fetches
};

// --- Utility ---
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

const backoff = async (attempt) => {
  const delay = Math.min(CONFIG.BACKOFF_MS * 2 ** attempt, CONFIG.MAX_BACKOFF);
  await sleep(delay + Math.random() * 300);
};

// GitHub's rate-limit window can take up to ~an hour to reset. Blocking that
// long inside a job holds a worker/queue slot the whole time and leaves the
// job stuck "in_progress" with no feedback to the caller. Fail fast with a
// clear message instead so the job is marked "failed" and the caller can
// surface/retry, rather than hanging indefinitely.
const throttleForRateLimit = async (remaining, reset) => {
  if (remaining > CONFIG.RATE_THRESHOLD || reset <= Date.now()) return;

  const wait = Math.max(reset - Date.now() + 5000, 0);

  if (wait > CONFIG.MAX_RATE_LIMIT_WAIT_MS) {
    const resetDate = new Date(reset).toISOString();
    const err = new Error(
      `GitHub API rate limit nearly exhausted (remaining=${remaining}). Resets at ${resetDate}. Please retry after that time.`
    );
    err.rateLimited = true;
    throw err;
  }

  console.warn(
    `[GitHubRate] Low remaining=${remaining}. Sleeping ${Math.round(wait / 1000)}s`
  );
  await sleep(wait);
};

// --- GraphQL fetcher with rate-limit protection ---
const fetchGraphQL = async (token, query, variables = {}, attempt = 0) => {
  try {
    const res = await axios.post(
      "https://api.github.com/graphql",
      { query, variables },
      {
        headers: {
          Authorization: `Bearer ${token}`,
          Accept: "application/vnd.github+json",
        },
        timeout: 60000,
      }
    );

    const remaining = +res.headers["x-ratelimit-remaining"] || 0;
    const reset = (+res.headers["x-ratelimit-reset"] || 0) * 1000;

    await throttleForRateLimit(remaining, reset);

    if (res.data.errors) throw new Error(JSON.stringify(res.data.errors));
    return res.data.data;
  } catch (err) {
    if (!err.rateLimited && attempt < 4) {
      await backoff(attempt);
      return fetchGraphQL(token, query, variables, attempt + 1);
    }
    throw err;
  }
};

// --- GraphQL-based incremental fetch for user repositories ---
const fetchIncrementalUserRepos = async (token, login, lastFetchedAt, pageSize = CONFIG.INCREMENTAL_PAGE_SIZE) => {
  const lastFetchedDate = new Date(lastFetchedAt);
  let repos = [];
  let after = null;
  let hasNext = true;
  let shouldStop = false;

  console.log(`[IncrementalFetch] Starting incremental fetch for user ${login}, lastFetched: ${lastFetchedDate.toISOString()}`);

  while (hasNext && !shouldStop) {
    const data = await fetchGraphQL(token, USER_REPOS_QUERY, {
      login,
      after,
      pageSize,
    });

    if (!data.user?.repositories) {
      console.warn(`[IncrementalFetch] No repositories found for user ${login}`);
      break;
    }

    const { nodes, pageInfo } = data.user.repositories;

    for (const repo of nodes) {
      const repoUpdatedAt = new Date(repo.updatedAt);
      
      // Stop if we've reached repos older than lastFetchedAt
      if (repoUpdatedAt <= lastFetchedDate) {
        console.log(`[IncrementalFetch] Stopping: repo ${repo.name} updated at ${repoUpdatedAt.toISOString()} <= ${lastFetchedDate.toISOString()}`);
        shouldStop = true;
        break;
      }

      repos.push(repo);
    }

    hasNext = pageInfo.hasNextPage && !shouldStop;
    after = pageInfo.endCursor;

    console.log(`[IncrementalFetch] Fetched ${nodes.length} repos, total: ${repos.length}, hasNext: ${hasNext}, shouldStop: ${shouldStop}`);
  }

  console.log(`[IncrementalFetch] Completed. Found ${repos.length} updated repositories`);
  return repos;
};

// --- GraphQL-based incremental fetch for organization repositories ---
const fetchIncrementalOrgRepos = async (token, login, lastFetchedAt, pageSize = CONFIG.INCREMENTAL_PAGE_SIZE) => {
  const lastFetchedDate = new Date(lastFetchedAt);
  let repos = [];
  let after = null;
  let hasNext = true;
  let shouldStop = false;

  console.log(`[IncrementalFetch] Starting incremental fetch for org ${login}, lastFetched: ${lastFetchedDate.toISOString()}`);

  while (hasNext && !shouldStop) {
    const data = await fetchGraphQL(token, ORG_REPOS_QUERY, {
      login,
      after,
      pageSize,
    });

    if (!data.organization?.repositories) {
      console.warn(`[IncrementalFetch] No repositories found for organization ${login}`);
      break;
    }

    const { nodes, pageInfo } = data.organization.repositories;

    for (const repo of nodes) {
      const repoUpdatedAt = new Date(repo.updatedAt);
      
      // Stop if we've reached repos older than lastFetchedAt
      if (repoUpdatedAt <= lastFetchedDate) {
        console.log(`[IncrementalFetch] Stopping: repo ${repo.name} updated at ${repoUpdatedAt.toISOString()} <= ${lastFetchedDate.toISOString()}`);
        shouldStop = true;
        break;
      }

      repos.push(repo);
    }

    hasNext = pageInfo.hasNextPage && !shouldStop;
    after = pageInfo.endCursor;

    console.log(`[IncrementalFetch] Fetched ${nodes.length} repos, total: ${repos.length}, hasNext: ${hasNext}, shouldStop: ${shouldStop}`);
  }

  console.log(`[IncrementalFetch] Completed. Found ${repos.length} updated repositories`);
  return repos;
};

// --- REST API search for incremental fetching with date filter (DEPRECATED - use GraphQL instead) ---
const searchRepositoriesREST = async (token, query, page = 1, perPage = 100, attempt = 0) => {
  try {
    const res = await axios.get(
      "https://api.github.com/search/repositories",
      {
        params: {
          q: query,
          sort: "updated",
          order: "desc",
          per_page: perPage,
          page: page,
        },
        headers: {
          Authorization: `Bearer ${token}`,
          Accept: "application/vnd.github+json",
        },
        timeout: 60000,
      }
    );

    const remaining = +res.headers["x-ratelimit-remaining"] || 0;
    const reset = (+res.headers["x-ratelimit-reset"] || 0) * 1000;

    await throttleForRateLimit(remaining, reset);

    return res.data;
  } catch (err) {
    if (!err.rateLimited && attempt < 4) {
      await backoff(attempt);
      return searchRepositoriesREST(token, query, page, perPage, attempt + 1);
    }
    throw err;
  }
};

// --- Queries ---
const REPO_QUERY = `
query($after:String,$pageSize:Int!){
  viewer{
    repositories(first:$pageSize,after:$after,ownerAffiliations:OWNER,orderBy:{field:UPDATED_AT,direction:DESC}){
      totalCount
      pageInfo{hasNextPage endCursor}
      nodes{
        name
        url
        isPrivate
        isArchived
        updatedAt
        stargazerCount
        forkCount
        refs(first:1,refPrefix:"refs/heads/"){
          totalCount
          nodes{
            name
            target{
              ...on Commit{
                history(first:1){
                  totalCount
                  nodes{ committedDate }
                }
              }
            }
          }
        }
      }
    }
  }
}`;

// Query for user installation repositories
const USER_REPOS_QUERY = `
query($login:String!,$after:String,$pageSize:Int!){
  user(login:$login){
    repositories(first:$pageSize,after:$after,ownerAffiliations:OWNER,orderBy:{field:UPDATED_AT,direction:DESC}){
      totalCount
      pageInfo{hasNextPage endCursor}
      nodes{
        name
        url
        isPrivate
        isArchived
        visibility
        updatedAt
        stargazerCount
        forkCount
        refs(first:1,refPrefix:"refs/heads/"){
          totalCount
          nodes{
            name
            target{
              ...on Commit{
                history(first:1){
                  totalCount
                  nodes{ committedDate }
                }
              }
            }
          }
        }
      }
    }
  }
}`;

// Query for organization installation repositories
const ORG_REPOS_QUERY = `
query($login:String!,$after:String,$pageSize:Int!){
  organization(login:$login){
    repositories(first:$pageSize,after:$after,orderBy:{field:UPDATED_AT,direction:DESC}){
      totalCount
      pageInfo{hasNextPage endCursor}
      nodes{
        name
        url
        isPrivate
        isArchived
        visibility
        updatedAt
        stargazerCount
        forkCount
        refs(first:1,refPrefix:"refs/heads/"){
          totalCount
          nodes{
            name
            target{
              ...on Commit{
                history(first:1){
                  totalCount
                  nodes{ committedDate }
                }
              }
            }
          }
        }
      }
    }
  }
}`;

// Legacy query name for backward compatibility
const INSTALLATION_REPOS_QUERY = USER_REPOS_QUERY;

const LANG_QUERY = `
query($owner:String!,$name:String!){
  repository(owner:$owner,name:$name){
    languages(first:10,orderBy:{field:SIZE,direction:DESC}){
      edges{size node{name color}} totalSize
    }
  }
}`;

const BRANCHES_QUERY = `
query($owner:String!,$name:String!,$after:String){
  repository(owner:$owner,name:$name){
    defaultBranchRef{
      name
    }
    refs(refPrefix:"refs/heads/",first:100,after:$after){
      pageInfo{hasNextPage endCursor}
      nodes{
        name
        target{
          ...on Commit{
            oid
            committedDate
            message
            author{
              name
              email
            }
          }
        }
      }
    }
  }
}`;
// Query to fetch complete repository details
const REPO_DETAILS_QUERY = `
  query($owner: String!, $name: String!) {
    repository(owner: $owner, name: $name) {
      stargazerCount
      forkCount
      defaultBranchRef {
        target {
          ... on Commit {
            history {
              totalCount
            }
          }
        }
      }
    }
  }
`;

// Query to fetch organization teams
const TEAMS_QUERY = `
  query($login: String!, $after: String) {
    organization(login: $login) {
      teams(first: 100, after: $after) {
        pageInfo {
          hasNextPage
          endCursor
        }
        nodes {
          id
          name
          slug
          description
          privacy
          members {
            totalCount
          }
          repositories {
            totalCount
          }
        }
      }
    }
  }
`;

// Query to fetch team members
const TEAM_MEMBERS_QUERY = `
  query($login: String!, $teamSlug: String!, $after: String) {
    organization(login: $login) {
      team(slug: $teamSlug) {
        members(first: 100, after: $after) {
          pageInfo {
            hasNextPage
            endCursor
          }
          edges {
            role
            node {
              id
              login
              name
              email
              avatarUrl
            }
          }
        }
      }
    }
  }
`;

/**
 * Fetch all teams for an organization along with their members
 * Only applicable for organization installations
 * Requires GitHub App to have "Members" organization permission (read)
 */
const fetchOrganizationTeams = async (token, login) => {
  try {
    console.log(`[TeamsFetch] Starting teams fetch for organization: ${login}`);
    let teams = [];
    let after = null;
    let hasNext = true;

    // Fetch all teams
    while (hasNext) {
      try {
        const data = await fetchGraphQL(token, TEAMS_QUERY, { login, after });
        
        if (!data.organization?.teams) {
          console.warn(`[TeamsFetch] No teams found for organization ${login}`);
          break;
        }

        const teamsData = data.organization.teams;
        if (teamsData?.nodes?.length) {
          teams.push(...teamsData.nodes);
        }

        hasNext = teamsData?.pageInfo?.hasNextPage || false;
        after = teamsData?.pageInfo?.endCursor || null;

        await sleep(100);
      } catch (error) {
        // Check if it's a permissions error
        const errorMessage = error.message || '';
        if (errorMessage.includes('FORBIDDEN') || errorMessage.includes('Resource not accessible')) {
          console.warn(`[TeamsFetch] Permission denied: GitHub App does not have access to organization teams.`);
          console.warn(`[TeamsFetch] To enable teams data: Grant "Members" organization permission (read) to the GitHub App.`);
          return []; // Return empty array instead of throwing
        }
        throw error; // Re-throw other errors
      }
    }

    if (teams.length === 0) {
      console.log(`[TeamsFetch] No teams found or accessible for organization ${login}`);
      return [];
    }

    console.log(`[TeamsFetch] Found ${teams.length} teams for organization ${login}`);

    // Fetch members for each team
    const teamsWithMembers = [];
    
    for (const team of teams) {
      let members = [];
      let memberAfter = null;
      let hasMemberNext = true;

      while (hasMemberNext) {
        try {
          const memberData = await fetchGraphQL(token, TEAM_MEMBERS_QUERY, { 
            login, 
            teamSlug: team.slug, 
            after: memberAfter 
          });

          if (!memberData.organization?.team?.members) {
            console.warn(`[TeamsFetch] No members found for team ${team.slug}`);
            break;
          }

          const membersData = memberData.organization.team.members;
          if (membersData?.edges?.length) {
            members.push(...membersData.edges);
          }

          hasMemberNext = membersData?.pageInfo?.hasNextPage || false;
          memberAfter = membersData?.pageInfo?.endCursor || null;

          await sleep(100);
        } catch (error) {
          console.warn(`[TeamsFetch] Error fetching members for team ${team.slug}:`, error.message);
          break; // Skip this team's members but continue with other teams
        }
      }

      teamsWithMembers.push({
        ...team,
        membersData: members
      });

      console.log(`[TeamsFetch] Fetched ${members.length} members for team ${team.name} (${team.slug})`);
    }

    console.log(`[TeamsFetch] Completed teams fetch for ${login}. Total teams: ${teamsWithMembers.length}`);
    return teamsWithMembers;
  } catch (error) {
    console.error(`[TeamsFetch] Error fetching teams for ${login}:`, error.message);
    // Return empty array instead of throwing to prevent job failure
    return [];
  }
};

module.exports = { 
  CONFIG, 
  sleep, 
  backoff, 
  fetchGraphQL,
  fetchIncrementalUserRepos,
  fetchIncrementalOrgRepos,
  searchRepositoriesREST, // Deprecated - use fetchIncrementalUserRepos or fetchIncrementalOrgRepos
  fetchOrganizationTeams,
  REPO_QUERY, 
  LANG_QUERY, 
  INSTALLATION_REPOS_QUERY, 
  USER_REPOS_QUERY,
  ORG_REPOS_QUERY,
  BRANCHES_QUERY, 
  REPO_DETAILS_QUERY,
  TEAMS_QUERY,
  TEAM_MEMBERS_QUERY
};
