const express = require('express');
const { getNotices, createNotice, deleteNotice } = require('../controllers/noticeController');
const { protect, authorize } = require('../middleware/authMiddleware');
const router = express.Router();

router.use(protect);

router.get('/', getNotices);
// Only admins or HR can create/delete notices
router.post('/', authorize('admin', 'hr'), createNotice);
router.delete('/:id', authorize('admin', 'hr'), deleteNotice);

module.exports = router;
