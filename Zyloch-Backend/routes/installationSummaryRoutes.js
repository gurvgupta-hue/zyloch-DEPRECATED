const express = require("express");
const router = express.Router();

const {
  startSummaryJob,
  getJobStatus,
  retryFailedJob,
  refreshInstallationData,
} = require("../controllers/installationSummaryController");
const authMiddleware = require("../middleware/auth");
const tenantGuard = require("../middleware/tenantGuard");
const requireCapability = require("../middleware/requireCapability");
const { requireActiveLicense } = require("../middleware/requireEntitlement");
const requireRepoSelection = require("../middleware/requireRepoSelection");

router.use(authMiddleware, tenantGuard);

// Ingest work pulls repositories against plan limits — needs a live license and,
// for an installation larger than the plan covers, a recorded repository choice
// (requireRepoSelection). Status reads stay open so an expired tenant can still
// see in-flight jobs.
router.post(
  "/:installationId/start",
  requireCapability("summary.refresh"),
  requireActiveLicense,
  requireRepoSelection,
  startSummaryJob
);

router.post(
  "/:installationId/refresh",
  requireCapability("summary.refresh"),
  requireActiveLicense,
  requireRepoSelection,
  refreshInstallationData
);

router.get("/status/:jobId", requireCapability("summary.read"), getJobStatus);

router.post(
  "/retry/:jobId",
  requireCapability("summary.refresh"),
  requireActiveLicense,
  retryFailedJob
);

module.exports = router;
