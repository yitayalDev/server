const router = require('express').Router();
const controller = require('../controllers/notificationController');

router.get('/', controller.getNotifications);
router.put('/mark-as-read', controller.markAsRead);

module.exports = router;
