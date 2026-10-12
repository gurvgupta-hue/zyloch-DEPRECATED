/**
 * Control-plane model registry (zyloch_control). Bound once to the single
 * control DB handle.
 */

const { getControlDb } = require('./connectionManager');

const organizationSchema = require('../models/schemas/control/organizationSchema');
const authIdentitySchema = require('../models/schemas/control/authIdentitySchema');
const installationIndexSchema = require('../models/schemas/control/installationIndexSchema');
const licensePlanSchema = require('../models/schemas/control/licensePlanSchema');
const tenantLicenseSchema = require('../models/schemas/control/tenantLicenseSchema');
const tenantMetricsSchema = require('../models/schemas/control/tenantMetricsSchema');
const platformEventSchema = require('../models/schemas/control/platformEventSchema');
const yaraRuleSchema = require('../models/schemas/control/yaraRuleSchema');

const CONTROL_SCHEMAS = [
  organizationSchema,
  authIdentitySchema,
  installationIndexSchema,
  licensePlanSchema,
  tenantLicenseSchema,
  tenantMetricsSchema,
  platformEventSchema,
  yaraRuleSchema,
];

function bindModel(conn, { modelName, schema, collection }) {
  if (conn.models[modelName]) {
    return conn.models[modelName];
  }
  return conn.model(modelName, schema, collection);
}

let cache = null;

/**
 * Resolve the control-plane models.
 * @returns {{ Organization, AuthIdentity, InstallationIndex, LicensePlan,
 *            TenantLicense, TenantMetrics, PlatformEvent, YaraRule, connection }}
 */
function getControlModels() {
  const conn = getControlDb();
  // Rebuild the cache if the underlying connection was recreated.
  if (cache && cache.connection === conn) {
    return cache;
  }
  const models = { connection: conn };
  for (const def of CONTROL_SCHEMAS) {
    models[def.modelName] = bindModel(conn, def);
  }
  cache = models;
  return models;
}

module.exports = { getControlModels, CONTROL_SCHEMAS };
