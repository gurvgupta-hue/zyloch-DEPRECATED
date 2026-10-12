/**
 * Database entrypoint for Strategy C (database-per-tenant).
 *
 * Opens the single shared cluster connection (which backs both the control DB
 * and all per-tenant DBs) and bootstraps the control plane (indexes + license
 * plan catalog). Returns once the control plane is ready to serve requests.
 */

const { connectCluster, closeAll } = require('../db/connectionManager');
const { bootstrapControlPlane } = require('../services/controlBootstrap');

async function connectDB(options = {}) {
  await connectCluster(options);
  await bootstrapControlPlane();
  return true;
}

module.exports = connectDB;
module.exports.connectDB = connectDB;
module.exports.closeAll = closeAll;
