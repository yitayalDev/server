const Subscription = require('../models/subscription');
const Employee = require('../models/employee');

/**
 * Middleware to check if the tenant has an active subscription.
 * Should be placed AFTER authMiddleware.protect
 */
exports.checkSubscription = async (req, res, next) => {
    try {
        // Find the subscription for this tenant (admin's ID)
        const subscription = await Subscription.findOne({ admin: req.user.tenantId });

        if (!subscription || subscription.status !== 'active') {
            return res.status(403).json({
                message: 'Active subscription required. Please upgrade your plan.',
                billingUrl: '/admin/billing'
            });
        }

        // Attach subscription info to req for limit checks in controllers
        req.subscription = subscription;
        next();
    } catch (err) {
        console.error('Subscription middleware error:', err);
        res.status(500).json({ message: 'Server error checking subscription' });
    }
};

/**
 * Helper to check plan limits (e.g., employee count)
 * This can be used inside controllers
 */
exports.getPlanLimits = (plan) => {
    const limits = {
        Starter: { maxEmployees: 50 },
        Pro: { maxEmployees: 200 },
        Enterprise: { maxEmployees: Infinity }
    };
    return limits[plan] || limits.Starter;
};
