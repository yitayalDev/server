const express = require('express');
const router = express.Router();
const { protect, authorizeOrPermission } = require('../middleware/authMiddleware');
const {
    checkIn,
    checkOut,
    getTodayStatus,
    getMyTimesheets,
    getAllAttendance,
} = require('../controllers/attendanceController');

// Employee routes
router.post('/check-in', protect, checkIn);
router.post('/check-out', protect, checkOut);
router.get('/today', protect, getTodayStatus);
router.get('/my', protect, getMyTimesheets);

// Admin route (accessible by admin or those with manage_attendance permission)
router.get('/', protect, authorizeOrPermission(['admin'], 'manage_attendance'), getAllAttendance);

module.exports = router;
