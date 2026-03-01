const express = require('express');
const router = express.Router();
const { protect, authorize } = require('../middleware/authMiddleware');
const {
    checkIn,
    checkOut,
    getTodayStatus,
    getMyTimesheets,
    getAllAttendance,
} = require('../controllers/attendanceController');

// Employee routes
router.post('/check-in', protect, authorize('employee'), checkIn);
router.post('/check-out', protect, authorize('employee'), checkOut);
router.get('/today', protect, authorize('employee'), getTodayStatus);
router.get('/my', protect, authorize('employee'), getMyTimesheets);

// Admin route
router.get('/', protect, authorize('admin'), getAllAttendance);

module.exports = router;
