const router = require('express').Router();
const path = require('path');
const multer = require('multer');
const {
  getLeaves,
  requestLeave,
  updateLeaveStatus
} = require('../controllers/leaveController');
const { protect, authorize } = require('../middleware/authMiddleware');
const Leave = require('../models/leave');

// Multer config for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) =>
    cb(null, path.join(__dirname, '../public/upload')),
  filename: (req, file, cb) =>
    cb(null, Date.now() + '-' + file.originalname),
});
const upload = multer({ storage });

/**
 * EMPLOYEE: My Leaves
 * Returns all leaves for the logged-in employee
 * ✅ Does NOT mark leaves as seen automatically
 */
router.get('/my', protect, authorize('employee'), async (req, res) => {
  try {
    const employeeId = req.user.employeeId || req.user.employee?._id;

    if (!employeeId) {
      return res.status(400).json({ message: 'Employee not found' });
    }

    // ✅ Just return leaves, do not update seen
    const leaves = await Leave.find({ employee: employeeId }).sort({
      createdAt: -1
    });

    res.json(leaves);
  } catch (error) {
    console.error('My leaves error:', error);
    res.status(500).json({ message: 'Error fetching leaves' });
  }
});

/**
 * EMPLOYEE: Mark a leave as seen
 */
router.put('/:id/seen', protect, authorize('employee'), async (req, res) => {
  try {
    const employeeId = req.user.employeeId || req.user.employee?._id;
    const leaveId = req.params.id;

    const leave = await Leave.findOneAndUpdate(
      { _id: leaveId, employee: employeeId },
      { $set: { seen: true } },
      { new: true }
    );

    if (!leave) {
      return res.status(404).json({ message: 'Leave not found' });
    }

    res.json({ message: 'Leave marked as seen', leave });
  } catch (error) {
    console.error('Mark seen error:', error);
    res.status(500).json({ message: 'Error marking leave as seen' });
  }
});

/**
 * EMPLOYEE: Request leave
 */
router.post(
  '/',
  protect,
  authorize('employee'),
  upload.single('file'),
  requestLeave
);

/**
 * ADMIN / HR: All leaves
 */
router.get('/', protect, authorize('admin', 'hr'), getLeaves);

/**
 * ADMIN / HR: Update leave status
 */
router.put('/:id/status', protect, authorize('admin', 'hr'), updateLeaveStatus);

module.exports = router;
