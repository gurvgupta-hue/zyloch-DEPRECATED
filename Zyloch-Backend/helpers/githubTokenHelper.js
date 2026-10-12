const { octoApp } = require('../config/github');

const tokenCache = new Map();

/**
 * Get Installation Access Token (cached)
 */
async function getInstallationToken(installationId) {
  const cached = tokenCache.get(installationId);
  if (cached && Date.now() < cached.expiresAt - 30_000) return cached.token;

  const installationOctokit = await octoApp.getInstallationOctokit(installationId);
  const auth = await installationOctokit.auth({ type: 'installation', installationId });

  const token = auth.token;
  const expiresAt = new Date(auth.expiresAt || Date.now() + 60 * 60 * 1000).getTime();
  tokenCache.set(installationId, { token, expiresAt });
  return token;
}

module.exports = { getInstallationToken };