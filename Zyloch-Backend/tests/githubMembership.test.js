const path = require('path');
const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');

const membershipPath = path.resolve(__dirname, '../helpers/githubMembership.js');

function loadMembership() {
  delete require.cache[membershipPath];
  return require('../helpers/githubMembership');
}

describe('KAN-51 github membership filter', () => {
  const prev = process.env.ENFORCE_GITHUB_MEMBERSHIP;

  afterEach(() => {
    if (prev === undefined) delete process.env.ENFORCE_GITHUB_MEMBERSHIP;
    else process.env.ENFORCE_GITHUB_MEMBERSHIP = prev;
    delete require.cache[membershipPath];
  });

  it('isEnforceGithubMembership defaults off', () => {
    delete process.env.ENFORCE_GITHUB_MEMBERSHIP;
    const { isEnforceGithubMembership } = loadMembership();
    assert.equal(isEnforceGithubMembership({}), false);
    assert.equal(isEnforceGithubMembership({ ENFORCE_GITHUB_MEMBERSHIP: 'true' }), true);
    assert.equal(isEnforceGithubMembership({ ENFORCE_GITHUB_MEMBERSHIP: 'TRUE' }), true);
    assert.equal(isEnforceGithubMembership({ ENFORCE_GITHUB_MEMBERSHIP: 'false' }), false);
  });

  it('filter is no-op when flag off', async () => {
    const { filterInstallationsByGithubMembership } = loadMembership();
    const installs = [
      { installationId: 1, account: { login: 'abc-prod', type: 'Organization' } },
      { installationId: 2, account: { login: 'abc-demo', type: 'Organization' } },
    ];
    const out = await filterInstallationsByGithubMembership(installs, 'meetsuvariya', {
      env: { ENFORCE_GITHUB_MEMBERSHIP: 'false' },
      isGithubOrgMember: async () => {
        throw new Error('should not call GitHub when flag off');
      },
    });
    assert.equal(out.length, 2);
  });

  it('filter keeps only installs where mocked GitHub API says member', async () => {
    const { filterInstallationsByGithubMembership } = loadMembership();
    const installs = [
      { installationId: 1, account: { login: 'abc-prod', type: 'Organization' } },
      { installationId: 2, account: { login: 'abc-demo', type: 'Organization' } },
      { installationId: 3, account: { login: 'abc-test', type: 'Organization' } },
    ];
    const out = await filterInstallationsByGithubMembership(installs, 'meetsuvariya', {
      env: { ENFORCE_GITHUB_MEMBERSHIP: 'true' },
      isGithubOrgMember: async ({ orgLogin }) => orgLogin === 'abc-prod' || orgLogin === 'abc-demo',
    });
    assert.deepEqual(
      out.map((i) => i.account.login),
      ['abc-prod', 'abc-demo']
    );
  });

  it('isGithubOrgMember uses mocked axios status codes', async () => {
    const { isGithubOrgMember } = loadMembership();
    const member = await isGithubOrgMember(
      {
        orgLogin: 'abc-prod',
        accountType: 'Organization',
        username: 'me',
        installationId: 99,
      },
      {
        getInstallationToken: async () => 'tok',
        axiosGet: async () => ({ status: 204 }),
      }
    );
    assert.equal(member, true);

    const notMember = await isGithubOrgMember(
      {
        orgLogin: 'abc-prod',
        accountType: 'Organization',
        username: 'me',
        installationId: 99,
      },
      {
        getInstallationToken: async () => 'tok',
        axiosGet: async () => ({ status: 404 }),
      }
    );
    assert.equal(notMember, false);
  });

  it('user account type matches login', async () => {
    const { isGithubOrgMember } = loadMembership();
    assert.equal(
      await isGithubOrgMember({
        orgLogin: 'alice',
        accountType: 'User',
        username: 'alice',
        installationId: 1,
      }),
      true
    );
    assert.equal(
      await isGithubOrgMember({
        orgLogin: 'alice',
        accountType: 'User',
        username: 'bob',
        installationId: 1,
      }),
      false
    );
  });
});

describe('KAN-51 listInstallationsForUser with membership flag', () => {
  const githubTokenHelperPath = path.resolve(__dirname, '../helpers/githubTokenHelper.js');
  const githubControllerPath = path.resolve(__dirname, '../controllers/github.js');
  const membershipHelperPath = path.resolve(__dirname, '../helpers/githubMembership.js');
  let tenantScope;
  let originalList;
  let originalFilter;
  const TENANT_A = '674a1b2c3d4e5f6789012345';

  beforeEach(() => {
    require.cache[githubTokenHelperPath] = {
      id: githubTokenHelperPath,
      filename: githubTokenHelperPath,
      loaded: true,
      exports: { getInstallationToken: async () => 'test-token' },
    };
    delete require.cache[githubControllerPath];
    tenantScope = require('../helpers/tenantScope');
    originalList = tenantScope.listInstallationsForTenant;
  });

  afterEach(() => {
    tenantScope.listInstallationsForTenant = originalList;
    if (originalFilter) {
      const membership = require('../helpers/githubMembership');
      membership.filterInstallationsByGithubMembership = originalFilter;
      originalFilter = undefined;
    }
    delete require.cache[githubTokenHelperPath];
    delete require.cache[githubControllerPath];
    delete require.cache[membershipHelperPath];
    delete process.env.ENFORCE_GITHUB_MEMBERSHIP;
  });

  it('returns all tenant installs when flag off', async () => {
    process.env.ENFORCE_GITHUB_MEMBERSHIP = 'false';
    tenantScope.listInstallationsForTenant = async () => [
      { installationId: 1, account: { login: 'a', type: 'Organization' } },
      { installationId: 2, account: { login: 'b', type: 'Organization' } },
    ];
    const githubController = require('../controllers/github');
    let payload;
    await githubController.listInstallationsForUser(
      { user: { login: 'me', role: 'member' }, tenant: { id: TENANT_A } },
      { json: (data) => { payload = data; } },
      () => {}
    );
    assert.equal(payload.installations.length, 2);
    assert.equal(payload.enforceGithubMembership, false);
  });
});
