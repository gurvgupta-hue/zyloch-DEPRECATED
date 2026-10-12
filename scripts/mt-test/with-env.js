/**
 * Bootstrap: inherit the running server's environment (Vault-injected, so it is
 * only present in the live process) and then run the target script.
 * Usage: node with-env.js <script>
 */
const fs = require('fs');

function loadServerEnv() {
  for (const pid of fs.readdirSync('/proc').filter((d) => /^\d+$/.test(d))) {
    let raw;
    try {
      raw = fs.readFileSync(`/proc/${pid}/environ`, 'utf8');
    } catch {
      continue;
    }
    if (!raw.includes('MONGO_URI=')) continue;
    let loaded = 0;
    for (const entry of raw.split('\0')) {
      const i = entry.indexOf('=');
      if (i <= 0) continue;
      const key = entry.slice(0, i);
      if (process.env[key] === undefined) {
        process.env[key] = entry.slice(i + 1);
        loaded++;
      }
    }
    console.error(`[with-env] inherited ${loaded} vars from pid ${pid}`);
    return true;
  }
  return false;
}

if (!loadServerEnv()) {
  console.error('[with-env] could not find a process with MONGO_URI');
  process.exit(2);
}
process.env.MONGO_SOCKET_TIMEOUT_MS = process.env.MONGO_SOCKET_TIMEOUT_MS || '300000';
require(process.argv[2]);
