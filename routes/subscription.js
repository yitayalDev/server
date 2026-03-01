const express = require('express');
const router = express.Router();
const {
    getPlans,
    createCheckoutSession,
    getSubscriptionStatus,
    getStripeInvoices,
    stripeWebhook
} = require('../controllers/subscriptionController');
const { protect, authorize } = require('../middleware/authMiddleware');

// Stripe Webhook MUST be raw body. 
// We export this separately or handle it in server.js before the global JSON parser.
// For simplicity in EMS architecture, we'll expose a separate middleware chain.

// Protected API Routes
router.get('/plans', protect, authorize('admin', 'finance'), getPlans);
router.get('/status', protect, authorize('admin', 'finance'), getSubscriptionStatus);
router.post('/checkout', protect, authorize('admin'), createCheckoutSession);
router.get('/invoices', protect, authorize('admin', 'finance'), getStripeInvoices);

// Note: webhook route is registered in server.js directly to bypass express.json()

module.exports = router;
