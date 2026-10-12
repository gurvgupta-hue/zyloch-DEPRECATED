/**
 * Tenant-aware MongoDB connection manager (Strategy C: database-per-tenant).
 *
 * Design goals:
 *  - A SINGLE physical connection (and therefore a single driver connection pool)
 *    is opened to the Atlas cluster. Per-tenant and control databases are accessed
 *    via `connection.useDb(dbName)` handles that all share that one pool. This avoids
 *    opening N independent pools (one per tenant) which would exhaust cluster sockets.
 *  - Per-tenant `useDb` handles (and their compiled models) are kept in a bounded
 *    LRU cache so memory does not grow without limit as tenants come and go.
 *  - Initial connect uses bounded retries with backoff.
 *  - Graceful teardown closes the single cluster connection.
 */

const mongoose = require('mongoose');

const CONTROL_DB_NAME = process.env.CONTROL_DATABASE_NAME || 'zyloch_control';
const TENANT_DB_PREFIX = process.env.TENANT_DB_PREFIX || 'zyloch_tenant_';
const MAX_TENANT_HANDLES = Number(process.env.MAX_TENANT_CONNECTIONS || 50);

const poolOptions = {
  maxPoolSize: Number(process.env.MONGO_MAX_POOL_SIZE || 20),
  minPoolSize: Number(process.env.MONGO_MIN_POOL_SIZE || 0),
  serverSelectionTimeoutMS: Number(process.env.MONGO_SERVER_SELECTION_TIMEOUT_MS || 10000),
  socketTimeoutMS: Number(process.env.MONGO_SOCKET_TIMEOUT_MS || 45000),
  maxIdleTimeMS: Number(process.env.MONGO_MAX_IDLE_TIME_MS || 60000),
};

let clusterConnection = null;
let controlDbHandle = null;

/** LRU cache of tenant DB handles: Map preserves insertion order. */
const tenantHandles = new Map(); // key: tenantId string -> { conn, dbName }

function getClusterUri() {
  const uri = process.env.MONGO_URI;
  if (!uri) {
    throw new Error('MONGO_URI is not defined in environment');
  }
  return uri;
}

function attachConnectionListeners(connection) {
  connection.on('connected', () => console.log('[db] Cluster connection established'));
  connection.on('disconnected', () => console.warn('[db] Cluster connection disconnected'));
  connection.on('reconnected', () => console.log('[db] Cluster connection reconnected'));
  connection.on('error', (err) => console.error('[db] Cluster connection error:', err.message));
}

/**
 * Open the single shared cluster connection with bounded retries.
 * Idempotent: returns the existing connection if already connected.
 */
async function connectCluster({ retries = 5, delayMs = 5000 } = {}) {
  if (clusterConnection && clusterConnection.readyState === 1) {
    return clusterConnection;
  }

  const uri = getClusterUri();
  let lastError;

  for (let attempt = 1; attempt <= retries; attempt++) {
    try {
      const connection = mongoose.createConnection(uri, poolOptions);
      attachConnectionListeners(connection);
      await connection.asPromise();
      clusterConnection = connection;
      controlDbHandle = connection.useDb(CONTROL_DB_NAME, { useCache: true });
      console.log(`[db] Connected to cluster; control DB="${CONTROL_DB_NAME}"`);
      return clusterConnection;
    } catch (err) {
      lastError = err;
      console.error(`[db] Cluster connect attempt ${attempt}/${retries} failed: ${err.message}`);
      if (attempt < retries) {
        await new Promise((resolve) => setTimeout(resolve, delayMs));
      }
    }
  }

  throw new Error(`MongoDB cluster connection failed after ${retries} attempts: ${lastError?.message}`);
}

function getClusterConnection() {
  if (!clusterConnection) {
    throw new Error('Cluster connection not initialized. Call connectCluster() first.');
  }
  return clusterConnection;
}

/** Control-plane DB handle (zyloch_control). */
function getControlDb() {
  if (!controlDbHandle) {
    throw new Error('Control DB not initialized. Call connectCluster() first.');
  }
  return controlDbHandle;
}

/**
 * A tenantId is always an `organizations._id`, i.e. a 24-character hex ObjectId.
 *
 * Validated before it is interpolated into a database name (MT-09.3). Nothing
 * today can reach here with attacker-controlled input — the value comes from a
 * signed JWT or the control plane — but the database name is the entire tenant
 * isolation boundary, so it should not be built from an unchecked string.
 */
const TENANT_ID_PATTERN = /^[0-9a-fA-F]{24}$/;

function assertValidTenantId(tenantId) {
  const value = String(tenantId);
  if (!TENANT_ID_PATTERN.test(value)) {
    throw new Error(`Invalid tenantId (expected a 24-character hex ObjectId): ${value}`);
  }
  return value;
}

function tenantDbName(tenantId) {
  return `${TENANT_DB_PREFIX}${assertValidTenantId(tenantId)}`;
}

/**
 * Resolve a per-tenant DB handle that shares the single cluster pool.
 * Handles are cached in a bounded LRU; eviction simply drops the reference
 * (the shared pool is untouched).
 */
function getTenantDb(tenantId) {
  if (!tenantId) {
    throw new Error('tenantId is required to resolve a tenant database');
  }
  const key = assertValidTenantId(tenantId);

  const cached = tenantHandles.get(key);
  if (cached) {
    // Refresh LRU recency.
    tenantHandles.delete(key);
    tenantHandles.set(key, cached);
    return cached.conn;
  }

  evictIfNeeded();

  const cluster = getClusterConnection();
  const dbName = tenantDbName(key);
  // useCache:false so we own the lifecycle via this LRU rather than mongoose's
  // unbounded internal cache.
  const conn = cluster.useDb(dbName, { useCache: false });
  tenantHandles.set(key, { conn, dbName });
  return conn;
}

function evictIfNeeded() {
  while (tenantHandles.size >= MAX_TENANT_HANDLES) {
    const oldestKey = tenantHandles.keys().next().value;
    if (oldestKey === undefined) break;
    tenantHandles.delete(oldestKey);
  }
}

function getCachedTenantCount() {
  return tenantHandles.size;
}

/** Close the single cluster connection and clear caches (graceful shutdown). */
async function closeAll() {
  tenantHandles.clear();
  controlDbHandle = null;
  if (clusterConnection) {
    await clusterConnection.close();
    clusterConnection = null;
    console.log('[db] Cluster connection closed');
  }
}

module.exports = {
  CONTROL_DB_NAME,
  TENANT_DB_PREFIX,
  MAX_TENANT_HANDLES,
  TENANT_ID_PATTERN,
  assertValidTenantId,
  connectCluster,
  getClusterConnection,
  getControlDb,
  getTenantDb,
  tenantDbName,
  getCachedTenantCount,
  closeAll,
};
