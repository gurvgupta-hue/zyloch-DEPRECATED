const express = require('express');
const router = express.Router();
const organizationController = require('../controllers/organization');
const membersController = require('../controllers/members');
const licenseController = require('../controllers/license');
const authMiddleware = require('../middleware/auth');
const tenantGuard = require('../middleware/tenantGuard');
const requireCapability = require('../middleware/requireCapability');
const publicDiscoveryLimiter = require('../middleware/publicDiscoveryLimiter');

// Public endpoint - check enabled providers (no auth required).
// Rate limited: the login page needs it before a session exists, so it stays
// public, but bulk probing of organization ids is throttled (MT-02.3).
router.get(
  '/:orgId/providers',
  publicDiscoveryLimiter,
  organizationController.getEnabledProviders
);

// All routes below are protected
router.use(authMiddleware);
router.use(tenantGuard);

// Get organization details
router.get('/', requireCapability('organization.read'), organizationController.getOrganization);

// Effective RBAC capabilities for the caller (drives frontend gates)
router.get('/capabilities', organizationController.getCapabilities);

// License (read for tenant; writes live in platform console)
router.get('/license', requireCapability('license.read'), licenseController.getLicense);

// Members (tenant-scoped)
router.get('/members', requireCapability('members.read'), membersController.listMembers);
router.post(
  '/members/invite',
  requireCapability('members.manage'),
  membersController.inviteMember
);
router.post(
  '/members/invites/:inviteId/revoke',
  requireCapability('members.manage'),
  membersController.revokeInvite
);
router.post(
  '/members/:userId/deactivate',
  requireCapability('members.manage'),
  membersController.deactivateMember
);
router.post(
  '/members/:userId/reactivate',
  requireCapability('members.manage'),
  membersController.reactivateMember
);
router.delete(
  '/members/:userId',
  requireCapability('members.manage'),
  membersController.deleteMember
);

// OAuth provider configuration (admin only)
router.put(
  '/oauth/google',
  requireCapability('organization.oauth.write'),
  organizationController.updateGoogleOAuth
);
router.put(
  '/oauth/microsoft',
  requireCapability('organization.oauth.write'),
  organizationController.updateMicrosoftOAuth
);
router.delete(
  '/oauth/google',
  requireCapability('organization.oauth.write'),
  organizationController.deleteGoogleOAuth
);
router.delete(
  '/oauth/microsoft',
  requireCapability('organization.oauth.write'),
  organizationController.deleteMicrosoftOAuth
);

// Get scan configurations
router.get('/scans', requireCapability('organization.read'), organizationController.getScanConfigurations);

// Update scan configurations (admin only)
router.put(
  '/scans',
  requireCapability('organization.settings.write'),
  organizationController.updateScanConfigurations
);

// Get automation configurations (auto-scan on installation sync)
router.get(
  '/automation',
  requireCapability('organization.read'),
  organizationController.getAutomationConfigurations
);

// Update automation configurations (admin only)
router.put(
  '/automation',
  requireCapability('organization.settings.write'),
  organizationController.updateAutomationConfigurations
);

// Get granular policy configurations (per-detector/policy toggles)
router.get('/policies', requireCapability('organization.read'), organizationController.getPolicyConfigurations);

// Update granular policy configurations (admin only)
router.put(
  '/policies',
  requireCapability('organization.settings.write'),
  organizationController.updatePolicyConfigurations
);

module.exports = router;
