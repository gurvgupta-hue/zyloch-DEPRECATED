const { App } = require('@octokit/app');
const createError = require('../utils/createError');
require('dotenv').config();
 
const appId = process.env.GITHUB_APP_ID;
let privateKey = process.env.GITHUB_PRIVATE_KEY;
 
try {
  if (!appId || !privateKey) {
    throw createError(500, 'GITHUB_APP_ID or GITHUB_PRIVATE_KEY not set properly.');
  }

  // 🔑 Convert escaped "\n" into actual newlines
  privateKey = privateKey.replace(/\\n/g, '\n').trim();

  // ✅ Validate the key looks like a PEM
  if (!privateKey.startsWith('-----BEGIN RSA PRIVATE KEY-----')) {
    throw createError(500, 'Invalid GitHub App private key format.');
  }

} catch (err) {
  console.error('GitHub App initialization error:', err.message);
  process.exit(1);
}

const octoApp = new App({
  appId,
  privateKey
});

module.exports = { octoApp };
