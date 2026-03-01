const express = require('express');
const { getNotices, createNotice, deleteNotice } = require('../controllers/noticeController');
const { protect, checkRole } = require('../middleware/authMiddleware');
const router = express.Router();

router.use(protect);

router.get('/', getNotices);
// Only admins or HR can create/delete notices
router.post('/', checkRole(['admin', 'hr']), createNotice);
router.delete('/:id', checkRole(['admin', 'hr']), deleteNotice);

module.exports = router;
