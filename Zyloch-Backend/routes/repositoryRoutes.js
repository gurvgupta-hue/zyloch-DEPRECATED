const express = require("express");
const router = express.Router();

const {
  getRepositoryData,
  getRepositoryBranches,
  deleteRepositoryData,
} = require("../controllers/repositoryController");
const authMiddleware = require("../middleware/auth");
const tenantGuard = require("../middleware/tenantGuard");
const requireCapability = require("../middleware/requireCapability");

router.use(authMiddleware, tenantGuard);

router.get("/:installationId", requireCapability("repositories.read"), getRepositoryData);

router.get(
  "/:installationId/:repositoryName/branches",
  requireCapability("repositories.read"),
  getRepositoryBranches
);

router.delete(
  "/:installationId/:repositoryName",
  requireCapability("repositories.delete"),
  deleteRepositoryData
);

module.exports = router;
