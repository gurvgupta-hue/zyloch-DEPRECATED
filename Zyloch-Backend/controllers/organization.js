const mongoose = require("mongoose");
const createError = require("../utils/createError");
const { getControlModels } = require("../db/controlModels");
const { getTenantModels } = require("../db/tenantModels");
const {
  countTenantUsers,
  countTenantRepos,
  getMonthlyScanUsage,
} = require("../services/licenseLimits");
const { ROLES, capabilitiesFor } = require("../services/rbac");
const {
  presentLimit,
  scannerEnabled,
  hasFeature,
  featureDisabled,
  normalizeScannerKey,
  FEATURE_KEYS,
} = require("../services/licenseEntitlements");
const { validateOAuthCallbackUrl } = require("../utils/validation");

// Maps each Scan Options card id → the license entitlement scanner key(s)
// that gate it. Mirrors SCAN_ID_TO_LICENSE_SCANNER_KEYS in
// Zyloch-Frontend/app/settings/components/ScanOptionsCard.js.
const SCAN_ID_TO_LICENSE_SCANNER_KEYS = {
  workflow: ['workflow'],
  iac: ['docker', 'kubernetes', 'terraform_aws', 'terraform_azure', 'terraform_gcp', 'bicep', 'ansible', 'cloudformation'],
  sbom: ['sbom'],
  'yaml-json': ['yaml-json'],
  'secret-scanner': ['secret_scanner'],
  yara: ['yara'],
  // Paid-tier scanners. Without an entry here isScanOptionLicensed() falls
  // through to "not gated" and a Free tenant is shown a toggle for a scan the
  // trigger endpoint will refuse.
  'skill-scanner': ['skill-scanner'],
  'cis-agent': ['cis-agent'],
};

/**
 * Scan Options ids governed by a feature rather than a scanner.
 *
 * AI-vs-human is not a scanner: it used to be gated on a scanner key
 * `ai_vs_human` that is absent from SCANNER_KEYS, so `hasScanner` only ever
 * returned true via the `all` wildcard — which handed it to Pro even though the
 * Pro plan sets `scanops.ai_vs_human: false`. The feature is the real authority.
 */
const SCAN_ID_TO_LICENSE_FEATURE_KEY = {
  'ai-vs-human': FEATURE_KEYS.SCANOPS_AI,
};

/** True if the tenant's plan licenses this Scan Options card. */
function isScanOptionLicensed(entitlements, scanId) {
  const featureKey = SCAN_ID_TO_LICENSE_FEATURE_KEY[scanId];
  if (featureKey) return hasFeature(entitlements, featureKey);

  const keys = SCAN_ID_TO_LICENSE_SCANNER_KEYS[scanId];
  if (!keys || keys.length === 0) return true; // unmapped ids are not license-gated
  return keys.some((key) => scannerEnabled(entitlements, key));
}

/** Fetch (or lazily create) the singleton tenant_settings doc. */
async function loadSettings(models, tenantId) {
  let settings = await models.TenantSettings.findOne({ tenantId });
  if (!settings) {
    settings = await models.TenantSettings.create({ tenantId });
  }
  return settings;
}

function sanitizeProvider(provider = {}) {
  return {
    enabled: !!provider.enabled,
    clientId: provider.clientId || null,
    redirectUri: provider.redirectUri || null,
    configuredAt: provider.configuredAt || null,
    hasClientSecret: !!provider.clientSecret,
  };
}

function sanitizeAutomation(automation = {}) {
  return { autoScanOnSync: !!automation.autoScanOnSync };
}

/** Get organization details for the current user */
async function getOrganization(req, res, next) {
  try {
    const { Organization } = getControlModels();
    const organization = await Organization.findById(req.tenantId);
    if (!organization) return next(createError(404, "Organization not found"));

    const settings = await loadSettings(req.models, req.tenantId);
    const admin = await req.models.User.findById(organization.adminUserId).select(
      "name email avatar_url login"
    );

    const [userCount, repoCount, scanUsage] = await Promise.all([
      countTenantUsers(req.tenantId),
      countTenantRepos(req.tenantId),
      getMonthlyScanUsage(req.tenantId),
    ]);

    const entitlements = req.license?.entitlements || {};
    const sanitizedOrg = {
      _id: organization._id,
      name: organization.name,
      adminUserId: admin,
      oauthConfigurations: {
        google: sanitizeProvider(settings.oauth?.google),
        microsoft: sanitizeProvider(settings.oauth?.microsoft),
      },
      scanConfigurations: settings.scans,
      automationConfigurations: sanitizeAutomation(settings.automation),
      license: req.license
        ? {
            planId: req.license.planId,
            planName: req.license.plan?.name || null,
            status: req.license.status,
            active: req.license.active,
            entitlements,
            usage: {
              // null == unlimited on the wire (per-seat / Enterprise plans).
              users: { current: userCount, max: presentLimit(entitlements.maxUsers) },
              repos: { current: repoCount, max: presentLimit(entitlements.maxRepos) },
              scansThisMonth: {
                current: scanUsage.count,
                max: presentLimit(entitlements.maxScansPerMonth),
                monthKey: scanUsage.monthKey,
              },
            },
          }
        : null,
      isActive: organization.isActive,
      createdAt: organization.createdAt,
      updatedAt: organization.updatedAt,
      userRole: req.user.role,
      githubLogin: req.user.login || admin?.login || null,
      authProvider: req.user.provider || null,
    };

    res.json({ success: true, organization: sanitizedOrg });
  } catch (err) {
    next(err);
  }
}

/** The plan feature governing each member-facing OAuth provider. */
const OAUTH_PROVIDER_FEATURE_KEYS = {
  google: FEATURE_KEYS.SETTINGS_OAUTH_GOOGLE,
  microsoft: FEATURE_KEYS.SETTINGS_OAUTH_MICROSOFT,
};

async function updateOAuthProvider(req, res, next, provider) {
  try {
    // Turning a provider off is always allowed; only switching one on has to be
    // licensed, so a downgraded tenant can still clean up its own configuration.
    if (
      req.body?.enabled &&
      featureDisabled(req.license?.entitlements, OAUTH_PROVIDER_FEATURE_KEYS[provider])
    ) {
      return next(
        createError(403, `${provider === 'google' ? 'Google' : 'Microsoft'} OAuth is not included in your plan`)
      );
    }

    const settings = await loadSettings(req.models, req.tenantId);
    const { clientId, clientSecret, redirectUri, enabled } = req.body;
    const current = settings.oauth[provider] || {};
    const touched = !!(clientId || clientSecret || redirectUri);
    // Security check carried over from main: a redirect URI must match the URI we
    // derive for this provider, so an admin cannot point the OAuth callback at an
    // attacker-controlled host. Applied per `provider` instead of main's two
    // hard-coded copies.
    const validatedRedirectUri = redirectUri
      ? validateOAuthCallbackUrl(redirectUri, provider)
      : current.redirectUri;

    settings.oauth[provider] = {
      enabled: enabled || false,
      clientId: clientId || current.clientId,
      clientSecret: clientSecret || current.clientSecret,
      redirectUri: validatedRedirectUri,
      configuredAt: touched ? new Date() : current.configuredAt,
      configuredBy: touched ? new mongoose.Types.ObjectId(req.user.id) : current.configuredBy,
    };
    settings.markModified("oauth");
    await settings.save();

    res.json({
      success: true,
      message: `${provider === "google" ? "Google" : "Microsoft"} OAuth configuration updated successfully`,
      configuration: sanitizeProvider(settings.oauth[provider]),
    });
  } catch (err) {
    next(err);
  }
}

async function deleteOAuthProvider(req, res, next, provider) {
  try {
    const settings = await loadSettings(req.models, req.tenantId);
    settings.oauth[provider] = {
      enabled: false,
      clientId: null,
      clientSecret: null,
      redirectUri: null,
      configuredAt: null,
      configuredBy: null,
    };
    settings.markModified("oauth");
    await settings.save();

    res.json({
      success: true,
      message: `${provider === "google" ? "Google" : "Microsoft"} OAuth configuration deleted successfully`,
    });
  } catch (err) {
    next(err);
  }
}

const updateGoogleOAuth = (req, res, next) => updateOAuthProvider(req, res, next, "google");
const updateMicrosoftOAuth = (req, res, next) => updateOAuthProvider(req, res, next, "microsoft");
const deleteGoogleOAuth = (req, res, next) => deleteOAuthProvider(req, res, next, "google");
const deleteMicrosoftOAuth = (req, res, next) => deleteOAuthProvider(req, res, next, "microsoft");

/**
 * Get enabled OAuth providers for an organization (PUBLIC endpoint, no auth).
 * Reads from the tenant's tenant_settings; orgId == tenantId.
 */
async function getEnabledProviders(req, res, next) {
  try {
    const { orgId } = req.params;
    if (!orgId || !mongoose.Types.ObjectId.isValid(orgId)) {
      return next(createError(400, "Valid organization ID is required"));
    }

    const { Organization } = getControlModels();
    const organization = await Organization.findById(orgId).select("isActive").lean();
    if (!organization || !organization.isActive) {
      return next(createError(404, "Organization not found"));
    }

    const models = getTenantModels(orgId);
    const settings = await models.TenantSettings.findOne({ tenantId: orgId }).lean();
    const google = settings?.oauth?.google || {};
    const microsoft = settings?.oauth?.microsoft || {};

    res.json({
      success: true,
      providers: {
        google: !!(google.enabled && google.clientId && google.clientSecret),
        microsoft: !!(microsoft.enabled && microsoft.clientId && microsoft.clientSecret),
      },
    });
  } catch (err) {
    next(err);
  }
}

/** Get scan configurations */
async function getScanConfigurations(req, res, next) {
  try {
    const settings = await loadSettings(req.models, req.tenantId);
    res.json({ success: true, scanConfigurations: settings.scans, userRole: req.user.role });
  } catch (err) {
    next(err);
  }
}

/** Get automation configurations */
async function getAutomationConfigurations(req, res, next) {
  try {
    const settings = await loadSettings(req.models, req.tenantId);
    res.json({
      success: true,
      automationConfigurations: sanitizeAutomation(settings.automation),
      userRole: req.user.role,
    });
  } catch (err) {
    next(err);
  }
}

/**
 * Update automation configurations (Admin only).
 *
 * Kept separate from `scanConfigurations`, which is a map of which scanners are
 * enabled. This controls *when* scans run, and the write path is explicit about
 * the keys it accepts so a future flag cannot be set by accident.
 */
async function updateAutomationConfigurations(req, res, next) {
  try {
    const { automationConfigurations } = req.body;
    if (!automationConfigurations || typeof automationConfigurations !== "object") {
      return next(createError(400, "Automation configurations are required"));
    }

    const settings = await loadSettings(req.models, req.tenantId);

    if ("autoScanOnSync" in automationConfigurations) {
      settings.automation.autoScanOnSync = !!automationConfigurations.autoScanOnSync;
    }

    await settings.save();

    res.json({
      success: true,
      message: "Automation configurations updated successfully",
      automationConfigurations: sanitizeAutomation(settings.automation),
    });
  } catch (err) {
    console.error("Error updating automation configurations:", err);
    next(err);
  }
}

/** Update scan configurations (Admin only) */
async function updateScanConfigurations(req, res, next) {
  try {
    const { scanConfigurations } = req.body;
    if (!scanConfigurations) {
      return next(createError(400, "Scan configurations are required"));
    }

    const entitlements = req.license?.entitlements || {};
    const blocked = [];
    const settings = await loadSettings(req.models, req.tenantId);
    Object.keys(scanConfigurations).forEach((key) => {
      const value = !!scanConfigurations[key];
      // A tenant's plan gates which scans can be switched on at all — enforced
      // here, not just in the UI, so a direct API call can't enable a scan the
      // license doesn't include. Leaves the existing value untouched.
      if (value && !isScanOptionLicensed(entitlements, key)) {
        blocked.push(key);
        return;
      }
      settings.scans[key] = value;
    });
    settings.markModified("scans");
    await settings.save();

    res.json({
      success: true,
      message: blocked.length
        ? `Scan configurations updated. Not included in your plan: ${blocked.join(", ")}.`
        : "Scan configurations updated successfully",
      scanConfigurations: settings.scans,
      blockedScanners: blocked,
    });
  } catch (err) {
    console.error("Error updating scan configurations:", err);
    next(err);
  }
}

/** Get granular policy configurations */
async function getPolicyConfigurations(req, res, next) {
  try {
    const settings = await loadSettings(req.models, req.tenantId);
    const policies = settings.policies || {};
    res.json({
      success: true,
      policyConfigurations: policies,
      // Flattened for callers that only care about per-scanner toggles (MT-08).
      scanners: policies.scanners || {},
      userRole: req.user.role,
    });
  } catch (err) {
    next(err);
  }
}

/**
 * Update granular policy configurations (admin only).
 *
 * Two shapes (MT-08):
 *   - `{ scanners: { <key>: { policies, enabled? } } }` — MERGE. Only the scanner
 *     keys present are touched. This is what the settings UI sends: the IaC panel
 *     and the Secrets panel save independently and must not clobber each other.
 *   - `{ policyConfigurations: {...} }` — full replace of the policies document.
 *
 * The merge shape replaces the GHAPP endpoint the frontend used to call directly,
 * which carried no tenant context and could not be authorized.
 */
async function updatePolicyConfigurations(req, res, next) {
  try {
    const { policyConfigurations, scanners } = req.body || {};

    if (!policyConfigurations && !scanners) {
      return next(
        createError(400, "Provide either `scanners` (partial) or `policyConfigurations` (replace)")
      );
    }
    if (scanners && (typeof scanners !== "object" || Array.isArray(scanners))) {
      return next(createError(400, "`scanners` must be an object keyed by scanner"));
    }

    const settings = await loadSettings(req.models, req.tenantId);
    const blocked = [];

    if (policyConfigurations) {
      settings.policies = policyConfigurations;
    } else {
      const entitlements = req.license?.entitlements || {};
      const current = settings.policies || {};
      const merged = { ...current, scanners: { ...(current.scanners || {}) } };

      for (const [scannerKey, scannerData] of Object.entries(scanners)) {
        if (!scannerData || typeof scannerData !== "object") continue;
        // Accept "detectors" as a legacy alias for "policies".
        const entry = { policies: scannerData.policies || scannerData.detectors || {} };
        if ("enabled" in scannerData) {
          const wantsEnabled = !!scannerData.enabled;
          // Same license gate as `/scans` above, at the per-scanner level this
          // endpoint also writes through (e.g. ScanOptionsCard's sync call).
          if (wantsEnabled && !scannerEnabled(entitlements, normalizeScannerKey(scannerKey))) {
            blocked.push(scannerKey);
          } else {
            entry.enabled = wantsEnabled;
          }
        }
        merged.scanners[scannerKey] = { ...(merged.scanners[scannerKey] || {}), ...entry };
      }

      merged.updatedAt = new Date();
      settings.policies = merged;
    }

    settings.markModified("policies");
    await settings.save();

    res.json({
      success: true,
      message: blocked.length
        ? `Policy configurations updated. Not included in your plan: ${blocked.join(", ")}.`
        : "Policy configurations updated successfully",
      policyConfigurations: settings.policies,
      scanners: settings.policies?.scanners || {},
      blockedScanners: blocked,
    });
  } catch (err) {
    console.error("Error updating policy configurations:", err);
    next(err);
  }
}

/**
 * Effective RBAC capabilities for the caller.
 * The frontend uses this to gate controls so the UI never renders an action
 * that the backend would reject with 403.
 */
async function getCapabilities(req, res, next) {
  try {
    const role = req.user.role;
    res.json({
      success: true,
      role,
      isAdmin: role === ROLES.ADMIN,
      capabilities: capabilitiesFor(role),
    });
  } catch (err) {
    next(err);
  }
}

module.exports = {
  // Exported for the drift guard in tests/scanEntitlementGating.test.js.
  SCAN_ID_TO_LICENSE_SCANNER_KEYS,
  SCAN_ID_TO_LICENSE_FEATURE_KEY,
  isScanOptionLicensed,
  getOrganization,
  getCapabilities,
  updateGoogleOAuth,
  updateMicrosoftOAuth,
  deleteGoogleOAuth,
  deleteMicrosoftOAuth,
  getEnabledProviders,
  getScanConfigurations,
  updateScanConfigurations,
  getAutomationConfigurations,
  updateAutomationConfigurations,
  getPolicyConfigurations,
  updatePolicyConfigurations,
};
