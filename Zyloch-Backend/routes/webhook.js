const express = require('express');
const router = express.Router();
const verifyWebhook = require('../middleware/verifyWebhook');
const webhookController = require('../controllers/webhook');

// ✅ Apply verification middleware before the controller
router.post('/github', verifyWebhook, webhookController.handleWebhook);

module.exports = router;
