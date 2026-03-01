const mongoose = require('mongoose');

const subscriptionSchema = new mongoose.Schema(
    {
        admin: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'User',
            required: true,
            unique: true // One admin = one subscription for the entire company
        },
        plan: {
            type: String,
            enum: ['Starter', 'Pro', 'Enterprise'],
            default: 'Starter'
        },
        status: {
            type: String,
            enum: ['active', 'past_due', 'canceled', 'incomplete', 'incomplete_expired', 'trialing', 'unpaid'],
            default: 'active'
        },
        stripeCustomerId: {
            type: String,
            default: null
        },
        stripeSubscriptionId: {
            type: String,
            default: null
        },
        currentPeriodEnd: {
            type: Date,
            default: null
        }
    },
    { timestamps: true }
);

module.exports = mongoose.model('Subscription', subscriptionSchema);
