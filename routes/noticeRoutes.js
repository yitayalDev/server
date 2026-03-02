const express = require('express');
const controller = require('../controllers/noticeController');
const { protect, authorizeOrPermission } = require('../middleware/authMiddleware');
const router = express.Router();

router.use(protect);

router.get('/', controller.getNotices);
// Only admins or HR can create/delete notices
router.post('/', authorizeOrPermission(['admin'], 'manage_notices'), controller.createNotice);
router.delete('/:id', authorizeOrPermission(['admin'], 'manage_notices'), controller.deleteNotice);

module.exports = router;
