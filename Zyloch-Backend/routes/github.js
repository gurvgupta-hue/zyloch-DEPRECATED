const express = require('express');
const router = express.Router();

const authMiddleware = require('../middleware/auth');
const tenantGuard = require('../middleware/tenantGuard');
const requireCapability = require('../middleware/requireCapability');
const installationController = require('../controllers/github');
const repoSelectionController = require('../controllers/repoSelection');

router.use(authMiddleware, tenantGuard);

router.get(
  '/',
  requireCapability('installations.read'),
  installationController.listInstallationsForUser
);

router.get(
  '/check-status',
  requireCapability('installations.read'),
  installationController.checkInstallationStatus
);

router.get(
  '/:installationId/repos',
  requireCapability('repositories.read'),
  installationController.listRepos
);

// --- Repository selection (over-limit installations) ---------------------------
// Registered before the '/:installationId/repos/...' family so the literal
// 'repo-selection' segment is never read as a repository path.
router.get(
  '/:installationId/repo-selection',
  requireCapability('repositories.read'),
  repoSelectionController.getState
);

router.get(
  '/:installationId/repo-selection/repos',
  requireCapability('repositories.read'),
  repoSelectionController.listCatalog
);

router.post(
  '/:installationId/repo-selection',
  requireCapability('repositories.selection.write'),
  repoSelectionController.saveState
);

router.post(
  '/:installationId/repo-selection/auto',
  requireCapability('repositories.selection.write'),
  repoSelectionController.autoSelectState
);

router.post(
  '/:installationId/repo-selection/sync',
  requireCapability('repositories.selection.write'),
  repoSelectionController.syncCatalog
);

router.get(
  '/:installationId/repos/:owner/:repo/branches',
  requireCapability('repositories.read'),
  installationController.listBranches
);

router.get(
  '/:installationId/repos/:owner/:repo/contents',
  requireCapability('repositories.read'),
  installationController.listContents
);

router.get(
  '/:installationId/repos/:owner/:repo/file',
  requireCapability('repositories.read'),
  installationController.getFileContent
);

module.exports = router;
