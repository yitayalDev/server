const router = require('express').Router();
const {
  getAdminSummary,
  getEmployeeSummary,
  getMonthlySalary,
  getLeaveAnalytics,
  getDepartmentAnalytics
} = require('../controllers/dashboardController');
const { protect, authorize } = require('../middleware/authMiddleware');

router.get('/admin', protect, authorize('admin'), getAdminSummary);
router.get('/employee/:employeeId', protect, authorize('employee'), getEmployeeSummary);

// Analytics
router.get('/analytics/salary', protect, authorize('admin', 'finance'), getMonthlySalary);
router.get('/analytics/leaves', protect, authorize('admin', 'hr'), getLeaveAnalytics);
router.get('/analytics/departments', protect, authorize('admin'), getDepartmentAnalytics);

module.exports = router;
