const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const mongoose = require('mongoose');
const {
  tenantDbName,
  TENANT_DB_PREFIX,
  getTenantDb,
} = require('../db/connectionManager');

describe('connectionManager', () => {
  it('builds tenant database name from tenant id', () => {
    const id = new mongoose.Types.ObjectId();
    assert.equal(tenantDbName(id), `${TENANT_DB_PREFIX}${id}`);
    assert.equal(tenantDbName(String(id)), `${TENANT_DB_PREFIX}${id}`);
  });

  it('requires tenantId to resolve a tenant database handle', () => {
    assert.throws(() => getTenantDb(null), /tenantId is required/);
    assert.throws(() => getTenantDb(''), /tenantId is required/);
  });
});
