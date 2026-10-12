const express = require('express');
const router = express.Router();

const {
  triggerScan,
  listScans,
  getLatestScan,
  getScanById,
  requestAutofix,
  createAutofixPr,
} = require('../controllers/scans');
const authMiddleware = require('../middleware/auth');
const tenantGuard = require('../middleware/tenantGuard');
const requireCapability = require('../middleware/requireCapability');
const { requireActiveLicense } = require('../middleware/requireEntitlement');

router.use(authMiddleware, tenantGuard);

// Triggering a scan consumes plan quota, so it needs a live license. Reads stay
// available on a lapsed license: a tenant must still be able to see the findings
// it has already paid for while it renews (MT-05.3).
router.post(
  '/',
  requireCapability('scans.trigger'),
  requireActiveLicense,
  triggerScan
);
// AI autofix (main #363/#376), tenant-scoped in controllers/scans.js.
router.post(
  '/ai/autofix',
  requireCapability('scans.autofix'),
  requireActiveLicense,
  requestAutofix
);
router.post(
  '/ai/autofix/pr',
  requireCapability('scans.autofix.pr'),
  requireActiveLicense,
  createAutofixPr
);

router.get('/latest', requireCapability('scans.read'), getLatestScan);
router.get('/:scanId', requireCapability('scans.read'), getScanById);
router.get('/', requireCapability('scans.read'), listScans);

module.exports = router;
