const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const mongoose = require('mongoose');

const {
  filterScansForTenant,
  assertScanBelongsToTenant,
  scanTenantOf,
} = require('../controllers/scans');
const { assertValidTenantId, tenantDbName } = require('../db/connectionManager');

const TENANT_A = '674a1b2c3d4e5f6789012345';
const TENANT_B = '674a1b2c3d4e5f6789012346';

const stamped = (tenantId, extra = {}) => ({ scan_id: 's1', tenantId, ...extra });
const metaStamped = (tenantId) => ({
  scan_id: 's2',
  scan_metadata: { tenantId },
});

describe('MT-09 scan tenant stamp reading', () => {
  it('reads a top-level stamp', () => {
    assert.equal(scanTenantOf(stamped(TENANT_A)), TENANT_A);
  });

  it('reads a scan_metadata stamp', () => {
    assert.equal(scanTenantOf(metaStamped(TENANT_A)), TENANT_A);
  });

  it('treats missing, null and empty stamps as unowned', () => {
    assert.equal(scanTenantOf({}), null);
    assert.equal(scanTenantOf({ tenantId: null }), null);
    assert.equal(scanTenantOf({ tenantId: '' }), null);
    assert.equal(scanTenantOf(undefined), null);
  });
});

describe('MT-09.1 filterScansForTenant fails closed', () => {
  it('keeps only this tenant scans', () => {
    const scans = [stamped(TENANT_A), stamped(TENANT_B), metaStamped(TENANT_A)];
    const kept = filterScansForTenant(scans, TENANT_A);
    assert.equal(kept.length, 2);
    assert.ok(kept.every((s) => scanTenantOf(s) === TENANT_A));
  });

  it('DROPS an unstamped scan instead of assuming ownership', () => {
    // The old behaviour returned this scan to whoever asked.
    const kept = filterScansForTenant([{ scan_id: 'orphan' }], TENANT_A);
    assert.deepEqual(kept, []);
  });

  it('drops a scan whose stamp is null or empty', () => {
    const kept = filterScansForTenant(
      [{ scan_id: 'a', tenantId: null }, { scan_id: 'b', tenantId: '' }],
      TENANT_A
    );
    assert.deepEqual(kept, []);
  });

  it('passes non-array input through unchanged', () => {
    assert.equal(filterScansForTenant(undefined, TENANT_A), undefined);
    assert.equal(filterScansForTenant(null, TENANT_A), null);
  });
});

describe('MT-09.2 assertScanBelongsToTenant fails closed', () => {
  it('accepts a scan stamped for this tenant', () => {
    assert.doesNotThrow(() => assertScanBelongsToTenant(stamped(TENANT_A), TENANT_A));
    assert.doesNotThrow(() => assertScanBelongsToTenant(metaStamped(TENANT_A), TENANT_A));
  });

  it('rejects another tenant scan', () => {
    assert.throws(
      () => assertScanBelongsToTenant(stamped(TENANT_B), TENANT_A),
      (err) => err.statusCode === 403
    );
  });

  it('REJECTS an unstamped scan instead of allowing it', () => {
    assert.throws(
      () => assertScanBelongsToTenant({ scan_id: 'orphan' }, TENANT_A),
      (err) => err.statusCode === 403
    );
  });
});

describe('MT-09.3 tenant database names are built from validated ids', () => {
  it('accepts a real ObjectId', () => {
    const id = new mongoose.Types.ObjectId();
    assert.equal(assertValidTenantId(id), String(id));
    assert.ok(tenantDbName(id).endsWith(String(id)));
  });

  it('rejects anything that is not a 24-char hex id', () => {
    for (const bad of [
      'demo-tenant',
      '../../admin',
      'zyloch_control',
      '674a1b2c3d4e5f678901234',   // 23 chars
      '674a1b2c3d4e5f67890123456', // 25 chars
      'ZZZa1b2c3d4e5f6789012345',  // non-hex
      '674a1b2c3d4e5f6789012345 ',
    ]) {
      assert.throws(
        () => tenantDbName(bad),
        /Invalid tenantId/,
        `expected rejection for ${JSON.stringify(bad)}`
      );
    }
  });
});
