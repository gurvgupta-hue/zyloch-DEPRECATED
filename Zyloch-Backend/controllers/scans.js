const createError = require('../utils/createError');
const { validatePositiveInteger, validateNonEmptyString } = require('../utils/validation');
const tenantScope = require('../helpers/tenantScope');
const ghappClient = require('../helpers/ghappClient');
const {
  assertScanCapacity,
  recordScanTriggered,
} = require('../services/licenseLimits');
const {
  scannerEnabled,
  normalizeScannerKey,
  expandScannerGroup,
  entitledScanners,
  SCANNER_KEYS,
} = require('../services/licenseEntitlements');

/**
 * Resolve which scanners a scan request may actually run (MT-05.2).
 *
 * Plan `scanners` is the authority for scan execution — it is per-scanner, while
 * the `features` map is coarser and drives UI/module gating. A request naming one
 * scanner is rejected outright when it is not entitled; `all` is narrowed to the
 * entitled set so it cannot silently mean "everything the platform ships".
 *
 * @returns {{ scanType: string, allowedScanTypes: string[] }}
 */
function resolveEntitledScanRequest(requestedScanType, entitlements) {
  const allowed = entitledScanners(entitlements);

  if (allowed.length === 0) {
    throw createError(403, 'Your plan does not include any scanners. Upgrade to run scans.');
  }

  const raw = String(requestedScanType || 'all').trim();
  if (!raw || raw === 'all') {
    return { scanType: 'all', allowedScanTypes: allowed };
  }

  // A group (`iac`, `terraform`) is a legitimate scan_type: GHAPP expands it to
  // its member scanners. Narrow it to the members this plan actually includes and
  // forward the group name — GHAPP intersects its expansion with allowedScanTypes,
  // so an unentitled member can never slip through.
  const groupMembers = expandScannerGroup(raw);
  if (groupMembers) {
    const entitledMembers = groupMembers.filter((key) => scannerEnabled(entitlements, key));
    if (entitledMembers.length === 0) {
      throw createError(403, `Scanner group not included in your plan: ${raw}`);
    }
    return { scanType: raw.toLowerCase(), allowedScanTypes: entitledMembers };
  }

  const scannerKey = normalizeScannerKey(raw);

  // Validate against the known scanner list first. `scannerEnabled` returns true
  // for any key when a plan holds the `all` wildcard, so without this an unknown
  // scan_type would pass entitlement and be forwarded downstream verbatim.
  if (!SCANNER_KEYS.includes(scannerKey)) {
    throw createError(400, `Unknown scan type: ${raw}`);
  }

  if (!scannerEnabled(entitlements, scannerKey)) {
    throw createError(403, `Scanner not included in your plan: ${scannerKey}`);
  }

  return { scanType: scannerKey, allowedScanTypes: [scannerKey] };
}

function readInstallationId(req) {
  return (
    req.body?.installation_id ??
    req.body?.installationId ??
    req.query?.installation_id ??
    req.query?.installationId
  );
}

async function resolveInstallationScope(req) {
  const raw = readInstallationId(req);
  if (!raw) {
    throw createError(400, 'installationId is required');
  }

  const installationId = validatePositiveInteger(raw, 'installationId');
  await tenantScope.assertInstallationBelongsToTenant(installationId, req.tenant.id);
  return String(installationId);
}

/**
 * Read the tenant a scan document claims to belong to (MT-09).
 * @returns {string|null} null when the document carries no tenant stamp at all.
 */
function scanTenantOf(scan) {
  const stamped = scan?.scan_metadata?.tenantId ?? scan?.tenantId;
  return stamped == null || stamped === '' ? null : String(stamped);
}

/**
 * Keep only scans owned by `tenantId`.
 *
 * FAILS CLOSED: a document with no tenant stamp is dropped, not kept. The old
 * `!scanTenantId || ...` treated an unstamped scan as belonging to whoever asked.
 * Scans already live in the tenant's own database and are reached through an
 * installation-ownership check, so this is defence in depth — but the default
 * has to point the safe way.
 */
function filterScansForTenant(scans, tenantId) {
  if (!Array.isArray(scans)) {
    return scans;
  }

  return scans.filter((scan) => {
    const owner = scanTenantOf(scan);
    if (owner === null) {
      console.warn('[scans] Dropping scan with no tenantId stamp', {
        scanId: scan?.scan_id ?? null,
        tenantId: String(tenantId),
      });
      return false;
    }
    return owner === String(tenantId);
  });
}

/** Reject a scan that is not stamped for this tenant. Fails closed (MT-09). */
function assertScanBelongsToTenant(scan, tenantId) {
  const owner = scanTenantOf(scan);
  if (owner === null) {
    console.warn('[scans] Rejecting scan with no tenantId stamp', {
      scanId: scan?.scan_id ?? null,
      tenantId: String(tenantId),
    });
    throw createError(403, 'Scan does not belong to your organization');
  }
  if (owner !== String(tenantId)) {
    throw createError(403, 'Scan does not belong to your organization');
  }
}

async function triggerScan(req, res, next) {
  try {
    const installationId = await resolveInstallationScope(req);
    const orgName = validateNonEmptyString(
      req.body.org_name || req.body.orgName,
      'org_name'
    );
    const repoName = validateNonEmptyString(
      req.body.repo_name || req.body.repoName,
      'repo_name'
    );
    const branch = req.body.branch || 'main';

    // Entitlement before quota: tell a tenant its plan excludes the scanner
    // rather than burning a scan slot on a request that cannot run.
    const { scanType, allowedScanTypes } = resolveEntitledScanRequest(
      req.body.scan_type || req.body.scanType,
      req.license?.entitlements
    );

    await assertScanCapacity(req.tenantId, {
      entitlements: req.license?.entitlements,
      active: req.license?.active,
    });

    const data = await ghappClient.ghappRequest('POST', '/scan', {
      data: {
        installation_id: installationId,
        org_name: orgName,
        repo_name: repoName,
        branch,
        scan_type: scanType,
        // Defence in depth: GHAPP intersects its resolved scan list with this,
        // so an entitlement can never be widened by a malformed scan_type.
        allowed_scan_types: allowedScanTypes,
      },
      timeout: 120000,
    });

    await recordScanTriggered(req.tenantId);

    res.json(data);
  } catch (err) {
    if (err.statusCode) return next(err);
    return next(createError(500, err.message));
  }
}

async function listScans(req, res, next) {
  try {
    const installationId = await resolveInstallationScope(req);
    const params = { installation_id: installationId };

    if (req.query.org_name) params.org_name = req.query.org_name;
    if (req.query.repo_name) params.repo_name = req.query.repo_name;
    if (req.query.limit) params.limit = req.query.limit;

    const data = await ghappClient.ghappRequest('GET', '/scans', { params });
    const scans = filterScansForTenant(data.scans, req.tenant.id);

    res.json({
      ...data,
      scans,
      total_count: scans.length,
      message: `Retrieved ${scans.length} scans`,
    });
  } catch (err) {
    if (err.statusCode) return next(err);
    return next(createError(500, err.message));
  }
}

async function getLatestScan(req, res, next) {
  try {
    const installationId = await resolveInstallationScope(req);
    const orgName = validateNonEmptyString(req.query.org_name, 'org_name');
    const repoName = validateNonEmptyString(req.query.repo_name, 'repo_name');
    const branch = req.query.branch || 'main';

    const params = {
      installation_id: installationId,
      org_name: orgName,
      repo_name: repoName,
      branch,
    };
    if (req.query.scan_type) params.scan_type = req.query.scan_type;

    const data = await ghappClient.ghappRequest('GET', '/scans/latest', { params });
    assertScanBelongsToTenant(data, req.tenant.id);
    res.json(data);
  } catch (err) {
    if (err.statusCode) return next(err);
    return next(createError(500, err.message));
  }
}

async function getScanById(req, res, next) {
  try {
    const installationId = await resolveInstallationScope(req);
    const scanId = validateNonEmptyString(req.params.scanId, 'scanId');

    const data = await ghappClient.ghappRequest('GET', `/scans/${encodeURIComponent(scanId)}`, {
      params: { installation_id: installationId },
    });

    assertScanBelongsToTenant(data, req.tenant.id);
    res.json(data);
  } catch (err) {
    if (err.statusCode) return next(err);
    return next(createError(500, err.message));
  }
}

/**
 * Proxy the AI autofix endpoints (main #363/#376) through the tenant boundary.
 *
 * The frontend used to call the scan service directly, which meant the only thing
 * standing between a caller and another tenant's installation was guessing an
 * installation id. Here the installation is checked against `req.tenant.id` first,
 * exactly as every other scan route does, and only then forwarded.
 *
 * Both consume paid capacity (a model call, and a write to a customer repo), so
 * they sit behind an active license like `scans.trigger` does.
 */
async function requestAutofix(req, res, next) {
  try {
    const installationId = await resolveInstallationScope(req);

    const data = await ghappClient.ghappRequest('POST', '/scans/ai/autofix', {
      data: {
        installation_id: installationId,
        policy_code: req.body.policy_code ?? null,
        policy_name: req.body.policy_name ?? null,
        description: req.body.description ?? '',
        severity: req.body.severity ?? null,
        file: req.body.file ?? null,
        line: req.body.line ?? null,
        scanner_type: req.body.scanner_type ?? null,
        code_block: req.body.code_block ?? '',
        force_refresh: !!req.body.force_refresh,
      },
      timeout: 120000,
    });

    res.json(data);
  } catch (err) {
    if (err.statusCode) return next(err);
    return next(createError(500, err.message));
  }
}

async function createAutofixPr(req, res, next) {
  try {
    const installationId = await resolveInstallationScope(req);
    const repository = validateNonEmptyString(req.body.repository, 'repository');
    const file = validateNonEmptyString(req.body.file, 'file');
    const proposal = validateNonEmptyString(req.body.proposal, 'proposal');
    const branch = req.body.branch || 'main';

    const data = await ghappClient.ghappRequest('POST', '/scans/ai/autofix/pr', {
      data: {
        installation_id: installationId,
        repository,
        branch,
        file,
        code_block: req.body.code_block ?? '',
        proposal,
      },
      timeout: 120000,
    });

    res.json(data);
  } catch (err) {
    if (err.statusCode) return next(err);
    return next(createError(500, err.message));
  }
}

module.exports = {
  triggerScan,
  requestAutofix,
  createAutofixPr,
  listScans,
  getLatestScan,
  getScanById,
  resolveInstallationScope,
  filterScansForTenant,
  assertScanBelongsToTenant,
  scanTenantOf,
  resolveEntitledScanRequest,
};
