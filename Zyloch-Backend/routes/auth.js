const express = require('express');
const router = express.Router();
const passport = require('passport');
const authController = require('../controllers/auth');  
const authMiddleware = require('../middleware/auth');
const { handleDynamicOAuth } = require('../helpers/dynamicOAuthHelper');

// ? GitHub OAuth (manual implementation)
router.get('/github', authController.startOAuth);
router.get('/github/callback', authController.oauthCallback);

// ? Google OAuth (Passport.js with dynamic credentials)
router.get('/google', 
  async (req, res, next) => {
    const orgId = req.query.orgId;
    if (!orgId) {
      return res.redirect(`${process.env.FRONTEND_URL}/login?error=google_requires_org`);
    }
    // Use dynamic OAuth with organization credentials
    return handleDynamicOAuth(req, res, next, 'google');
  }
);
router.get('/google/callback', 
  async (req, res, next) => {
    // Check if this is a dynamic OAuth callback (orgId in state)
    const orgId = req.query.state;
    if (!orgId) {
      return res.redirect(`${process.env.FRONTEND_URL}/login?error=google_requires_org`);
    }
    // Use dynamic OAuth handler for callback - this will authenticate the user
    handleDynamicOAuth(req, res, (err) => {
      if (err) {
        console.error('Google OAuth callback error:', err);
        return res.redirect(`${process.env.FRONTEND_URL}/login?error=google_auth_failed`);
      }
      
      // After successful authentication, user should be in req.user
      // Now handle the success (generate JWT and redirect)
      authController.googleOAuthCallback(req, res, next);
    }, 'google');
  }
);

// ? Microsoft OAuth (Passport.js with dynamic credentials)
// ✅ Microsoft login REQUIRES orgId - only allowed for organization members
router.get('/microsoft', 
  async (req, res, next) => {
    const orgId = req.query.orgId;
    if (!orgId) {
      // ✅ Reject Microsoft OAuth without orgId
      return res.redirect(`${process.env.FRONTEND_URL}/login?error=microsoft_requires_org`);
    }
    // Use dynamic OAuth with organization credentials
    return handleDynamicOAuth(req, res, next, 'microsoft');
  }
);
router.get('/microsoft/callback', 
  async (req, res, next) => {
    // Check if this is a dynamic OAuth callback (orgId in state)
    const orgId = req.query.state;
    if (!orgId) {
      // ✅ Reject Microsoft OAuth callback without orgId
      return res.redirect(`${process.env.FRONTEND_URL}/login?error=microsoft_requires_org`);
    }
    // Use dynamic OAuth handler for callback - this will authenticate the user
    handleDynamicOAuth(req, res, (err) => {
      if (err) {
        console.error('Microsoft OAuth callback error:', err);
        return res.redirect(`${process.env.FRONTEND_URL}/login?error=microsoft_auth_failed`);
      }
      
      // After successful authentication, user should be in req.user
      // Now handle the success (generate JWT and redirect)
      authController.microsoftOAuthCallback(req, res, next);
    }, 'microsoft');
  }
);

// ? Logout (works for all providers)
router.post('/logout', authController.logout);
router.post('/github/logout', authController.logout); // Keep for backward compatibility

// ? Identity Management (protected)
router.get('/identities', authMiddleware, authController.getLinkedIdentities);
router.post('/identities/unlink', authMiddleware, authController.unlinkIdentity);

// ? User Preferences (protected)
router.get('/preferences', authMiddleware, authController.getPreferences);
router.put('/preferences', authMiddleware, authController.updatePreferences);

// ? Current User (protected)
router.get('/me', authMiddleware, authController.getCurrentUser);

// ? Org switcher (KAN-49). Both require a session — an organization is only ever
// reachable from an identity that already belongs to it, never by lookup.
router.get('/organizations', authMiddleware, authController.listMyOrganizations);
router.post('/switch-organization', authMiddleware, authController.switchOrganization);

// ? Lightweight Protected Check (for client-side auth validation)
router.get('/check-auth', authController.checkAuth);

module.exports = router;
