#!/usr/bin/env node
/**
 * Tenant-contract audit (static — no server, no database).
 *
 * Every route must declare which side of the tenant boundary it is on:
 *   - protected : mounted behind `auth` + `tenantGuard`
 *   - public    : explicitly listed below, with a reason
 *
 * A route that is neither is a contract violation — the most likely way a new
 * endpoint leaks tenant data is simply forgetting the guards, and that mistake
 * looks fine in review.
 *
 * Usage:  node scripts/mt-test/contract-audit.js
 * Exit code is non-zero on any violation, so it can gate CI.
 */

const fs = require('fs');
const path = require('path');

const ROUTES_DIR = path.resolve(__dirname, '../../Zyloch-Backend/routes');

/**
 * Endpoints that are intentionally reachable without a session, and why.
 * Anything not listed here must sit behind auth + tenantGuard.
 */
const PUBLIC_ROUTES = {
  'auth.js': {
    '/github': 'OAuth entry point',
    '/github/callback': 'OAuth callback',
    '/google': 'OAuth entry point (requires orgId)',
    '/google/callback': 'OAuth callback',
    '/microsoft': 'OAuth entry point (requires orgId)',
    '/microsoft/callback': 'OAuth callback',
    '/logout': 'clears the cookie; nothing to leak',
    '/github/logout': 'legacy alias for logout',
    '/check-auth': 'session probe; returns 401 when invalid',
    '/resolve-org': 'pre-login org picker — rate limited, tenantId only (MT-02.2)',
  },
  'organization.js': {
    '/:orgId/providers': 'pre-login provider list — rate limited, booleans only (MT-02.3)',
  },
  'webhook.js': {
    '/github': 'GitHub HMAC-authenticated, not session-authenticated (MT-04)',
  },
};

const violations = [];
const summary = [];

function auditFile(file) {
  const source = fs.readFileSync(path.join(ROUTES_DIR, file), 'utf8');
  const publicForFile = PUBLIC_ROUTES[file] || {};

  // Does the file apply the guards to everything below a `router.use(...)`?
  const guardLine = source.match(/router\.use\(([^)]*)\)/g) || [];
  const guardsAll = guardLine.some((g) => /auth/i.test(g)) ;
  const tenantGuardsAll =
    guardLine.some((g) => /tenantGuard/.test(g)) || /router\.use\(tenantGuard\)/.test(source);

  const routeRe = /router\.(get|post|put|patch|delete)\(\s*(['"`])([^'"`]+)\2([\s\S]*?)\);/g;
  let match;
  while ((match = routeRe.exec(source)) !== null) {
    const [, method, , routePath, rest] = match;
    const declaredPublic = Object.prototype.hasOwnProperty.call(publicForFile, routePath);
    const inlineAuth = /authMiddleware|authController|verifyWebhook/.test(rest);
    const hasCapability = /requireCapability\(/.test(rest);
    const hasEntitlement = /requireActiveLicense|requireFeature|requireScanner|requireLimit/.test(rest);
    const rateLimited = /publicDiscoveryLimiter/.test(rest);

    // A route declared before `router.use(auth)` is not covered by it.
    const routeIndex = match.index;
    const guardIndex = source.search(/router\.use\([^)]*auth/i);
    const coveredByUse = guardsAll && guardIndex !== -1 && routeIndex > guardIndex;

    const protectedRoute = coveredByUse || inlineAuth;

    if (declaredPublic) {
      summary.push({
        file,
        route: `${method.toUpperCase()} ${routePath}`,
        state: 'public',
        note: publicForFile[routePath] + (rateLimited ? ' [rate limited]' : ''),
      });
      continue;
    }

    if (!protectedRoute) {
      violations.push({
        file,
        route: `${method.toUpperCase()} ${routePath}`,
        problem:
          'reachable without auth and not declared public — add auth+tenantGuard, or list it in PUBLIC_ROUTES with a reason',
      });
      continue;
    }

    if (coveredByUse && !tenantGuardsAll && !/tenantGuard/.test(rest)) {
      violations.push({
        file,
        route: `${method.toUpperCase()} ${routePath}`,
        problem: 'authenticated but no tenantGuard — request could run without tenant context',
      });
      continue;
    }

    summary.push({
      file,
      route: `${method.toUpperCase()} ${routePath}`,
      state: 'protected',
      note: [hasCapability ? 'capability' : null, hasEntitlement ? 'entitlement' : null]
        .filter(Boolean)
        .join(' + ') || 'auth + tenantGuard',
    });
  }
}

for (const file of fs.readdirSync(ROUTES_DIR).filter((f) => f.endsWith('.js'))) {
  auditFile(file);
}

console.log('\nTenant contract audit\n');
const byFile = {};
for (const row of summary) (byFile[row.file] ||= []).push(row);

for (const [file, rows] of Object.entries(byFile)) {
  console.log(`  ${file}`);
  for (const r of rows) {
    const tag = r.state === 'public' ? 'PUBLIC   ' : 'protected';
    console.log(`    ${tag} ${r.route.padEnd(58)} ${r.note}`);
  }
  console.log('');
}

const publicCount = summary.filter((s) => s.state === 'public').length;
console.log(`  ${summary.length} routes: ${summary.length - publicCount} protected, ${publicCount} intentionally public`);

if (violations.length > 0) {
  console.log(`\n✗ ${violations.length} contract violation(s):\n`);
  for (const v of violations) {
    console.log(`   ${v.file}  ${v.route}\n      ${v.problem}\n`);
  }
  process.exit(1);
}
console.log('\n✓ every route is either guarded or explicitly declared public\n');
