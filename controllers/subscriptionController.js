const stripeSecretKey = process.env.STRIPE_SECRET_KEY || 'sk_test_placeholder';
const stripe = require('stripe')(stripeSecretKey);
const Subscription = require('../models/subscription');
const User = require('../models/user');

const PLANS = {
    Starter: {
        priceId: process.env.STRIPE_PRICE_STARTER || 'price_starter_placeholder',
        price: 49,
        features: ['Up to 50 employees', 'Basic Reporting', 'Email Support']
    },
    Pro: {
        priceId: process.env.STRIPE_PRICE_PRO || 'price_pro_placeholder',
        price: 99,
        features: ['Up to 200 employees', 'Advanced Analytics', 'Priority Support', 'Custom Roles (RBAC)']
    },
    Enterprise: {
        priceId: process.env.STRIPE_PRICE_ENTERPRISE || 'price_enterprise_placeholder',
        price: 249,
        features: ['Unlimited employees', 'Dedicated Account Manager', '24/7 Phone Support', 'Custom Integrations']
    }
};

exports.getPlans = (req, res) => {
    res.json(PLANS);
};

exports.getSubscriptionStatus = async (req, res) => {
    try {
        const userId = req.user._id;
        let subscription = await Subscription.findOne({ admin: userId });

        if (!subscription) {
            // Create a default free "Starter" plan if none exists
            subscription = new Subscription({
                admin: userId,
                plan: 'Starter',
                status: 'active'
            });
            await subscription.save();
        }

        res.json(subscription);
    } catch (err) {
        console.error('getSubscriptionStatus error:', err);
        res.status(500).json({ message: 'Server error' });
    }
};

exports.createCheckoutSession = async (req, res) => {
    try {
        const { plan } = req.body;
        const userId = req.user._id;

        if (!PLANS[plan]) {
            return res.status(400).json({ message: 'Invalid plan selected' });
        }

        // Get or create local subscription
        let localSub = await Subscription.findOne({ admin: userId });
        if (!localSub) {
            localSub = new Subscription({ admin: userId });
            await localSub.save();
        }

        const user = await User.findById(userId);

        // Create Stripe Checkout Session
        const session = await stripe.checkout.sessions.create({
            payment_method_types: ['card'],
            mode: 'subscription',
            line_items: [
                {
                    price: PLANS[plan].priceId,
                    quantity: 1,
                },
            ],
            customer_email: user.email,
            client_reference_id: userId.toString(),
            metadata: {
                planName: plan
            },
            // Using frontend URL via env var or falling back
            success_url: `${process.env.CLIENT_URL || 'http://localhost:5173'}/admin/billing?success=true`,
            cancel_url: `${process.env.CLIENT_URL || 'http://localhost:5173'}/admin/billing?canceled=true`,
        });

        res.json({ url: session.url });
    } catch (err) {
        console.error('createCheckoutSession error:', err);
        res.status(500).json({ message: 'Server error while creating checkout session' });
    }
};

exports.getStripeInvoices = async (req, res) => {
    try {
        const userId = req.user._id;
        const localSub = await Subscription.findOne({ admin: userId });

        if (!localSub || !localSub.stripeCustomerId) {
            return res.json([]); // No invoices yet
        }

        const invoices = await stripe.invoices.list({
            customer: localSub.stripeCustomerId,
            limit: 10,
        });

        const formatted = invoices.data.map(inv => ({
            id: inv.id,
            amount: inv.amount_paid / 100,
            status: inv.status,
            date: new Date(inv.created * 1000).toISOString(),
            pdfUrl: inv.invoice_pdf,
        }));

        res.json(formatted);
    } catch (err) {
        console.error('getStripeInvoices error:', err);
        res.status(500).json({ message: 'Server error fetching invoices' });
    }
};

/**
 * Handle Stripe Webhooks
 * Note: Must use raw body parser in server.js for this route ONLY
 */
exports.stripeWebhook = async (req, res) => {
    const sig = req.headers['stripe-signature'];
    const endpointSecret = process.env.STRIPE_WEBHOOK_SECRET;

    let event;
    try {
        if (endpointSecret) {
            event = stripe.webhooks.constructEvent(req.body, sig, endpointSecret);
        } else {
            // For local testing without webhook secret configured
            event = req.body;
            if (typeof event === 'string') event = JSON.parse(event);
        }
    } catch (err) {
        console.error(`Webhook Error: ${err.message}`);
        return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    // Handle the event
    try {
        switch (event.type) {
            case 'checkout.session.completed': {
                const session = event.data.object;
                const userId = session.client_reference_id;
                const planName = session.metadata.planName;

                if (userId && planName) {
                    // Sync with local DB
                    await Subscription.findOneAndUpdate(
                        { admin: userId },
                        {
                            plan: planName,
                            status: 'active',
                            stripeCustomerId: session.customer,
                            stripeSubscriptionId: session.subscription,
                        },
                        { upsert: true }
                    );
                }
                break;
            }
            case 'customer.subscription.updated':
            case 'customer.subscription.deleted': {
                const subscription = event.data.object;
                await Subscription.findOneAndUpdate(
                    { stripeSubscriptionId: subscription.id },
                    {
                        status: subscription.status,
                        currentPeriodEnd: new Date(subscription.current_period_end * 1000),
                    }
                );
                break;
            }
            default:
                // Unhandled event type
                break;
        }
    } catch (err) {
        console.error('Error processing webhook:', err);
    }

    // Return a 200 response to acknowledge receipt of the event
    res.send();
};
