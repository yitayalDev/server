const Notification = require('../models/notification');

exports.getNotifications = async (req, res) => {
    try {
        const notifications = await Notification.find({
            recipient: req.user._id,
            tenantId: req.user.tenantId
        }).sort({ createdAt: -1 }).limit(20);
        res.json(notifications);
    } catch (err) {
        res.status(500).json({ message: 'Server error fetching notifications' });
    }
};

exports.markAsRead = async (req, res) => {
    try {
        await Notification.updateMany(
            { recipient: req.user._id, tenantId: req.user.tenantId, isRead: false },
            { isRead: true }
        );
        res.json({ message: 'Notifications marked as read' });
    } catch (err) {
        res.status(500).json({ message: 'Server error updating notifications' });
    }
};

// Internal helper for other controllers to send notifications
exports.sendNotification = async ({ tenantId, recipient, message, type, link }) => {
    try {
        await Notification.create({ tenantId, recipient, message, type, link });
    } catch (err) {
        console.error('sendNotification error:', err);
    }
};
