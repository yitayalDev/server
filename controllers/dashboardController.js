const Employee = require('../models/employee');
const Department = require('../models/department');
const Leave = require('../models/leave');
const Salary = require('../models/salary');
const mongoose = require('mongoose');

exports.getAdminSummary = async (req, res) => {
  try {
    const totalEmployees = await Employee.countDocuments({ tenantId: req.user.tenantId });
    const totalDepartments = await Department.countDocuments({ tenantId: req.user.tenantId });
    const pendingLeaves = await Leave.countDocuments({ tenantId: req.user.tenantId, status: 'pending' });

    res.json({ totalEmployees, totalDepartments, pendingLeaves });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
};

exports.getEmployeeSummary = async (req, res) => {
  try {
    const employeeId = req.params.employeeId;
    const totalLeaves = await Leave.countDocuments({ employee: employeeId, tenantId: req.user.tenantId });
    const pendingLeaves = await Leave.countDocuments({
      employee: employeeId,
      status: 'pending',
      tenantId: req.user.tenantId
    });

    res.json({ totalLeaves, pendingLeaves });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
};

// ─── Analytics ───────────────────────────────────────────────────────────────

const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

const lastNMonthsDate = (n) => {
  const d = new Date();
  d.setMonth(d.getMonth() - (n - 1));
  d.setDate(1);
  d.setHours(0, 0, 0, 0);
  return d;
};

/**
 * GET /api/dashboard/analytics/salary
 * Monthly salary spending for the last 12 months.
 */
exports.getMonthlySalary = async (req, res) => {
  try {
    const data = await Salary.aggregate([
      { $match: { payDate: { $gte: lastNMonthsDate(12) }, tenantId: req.user.tenantId } },
      {
        $group: {
          _id: { year: { $year: '$payDate' }, month: { $month: '$payDate' } },
          totalNet: { $sum: '$netSalary' },
          totalBasic: { $sum: '$basic' },
          count: { $sum: 1 },
        },
      },
      { $sort: { '_id.year': 1, '_id.month': 1 } },
    ]);

    const result = data.map((d) => ({
      month: `${MONTHS[d._id.month - 1]} ${d._id.year}`,
      totalNet: Math.round(d.totalNet),
      totalBasic: Math.round(d.totalBasic),
      employees: d.count,
    }));

    res.json(result);
  } catch (err) {
    console.error('getMonthlySalary:', err);
    res.status(500).json({ message: 'Server error' });
  }
};

/**
 * GET /api/dashboard/analytics/leaves
 * Leave frequency by type (pie) and by month (bar).
 */
exports.getLeaveAnalytics = async (req, res) => {
  try {
    const byType = await Leave.aggregate([
      { $match: { tenantId: req.user.tenantId } },
      { $group: { _id: '$leaveType', count: { $sum: 1 } } },
      { $sort: { count: -1 } },
    ]);

    const byMonth = await Leave.aggregate([
      { $match: { createdAt: { $gte: lastNMonthsDate(12) }, tenantId: req.user.tenantId } },
      {
        $group: {
          _id: {
            year: { $year: '$createdAt' },
            month: { $month: '$createdAt' },
            status: '$status',
          },
          count: { $sum: 1 },
        },
      },
      { $sort: { '_id.year': 1, '_id.month': 1 } },
    ]);

    const monthMap = {};
    byMonth.forEach(({ _id, count }) => {
      const key = `${MONTHS[_id.month - 1]} ${_id.year}`;
      if (!monthMap[key]) monthMap[key] = { month: key, approved: 0, pending: 0, rejected: 0 };
      monthMap[key][_id.status] = (monthMap[key][_id.status] || 0) + count;
    });

    res.json({
      byType: byType.map((d) => ({ name: d._id || 'Other', value: d.count })),
      byMonth: Object.values(monthMap),
    });
  } catch (err) {
    console.error('getLeaveAnalytics:', err);
    res.status(500).json({ message: 'Server error' });
  }
};

/**
 * GET /api/dashboard/analytics/departments
 * Employee count and leave count per department.
 */
exports.getDepartmentAnalytics = async (req, res) => {
  try {
    const tenantObjId = new mongoose.Types.ObjectId(req.user.tenantId);

    const empByDept = await Employee.aggregate([
      { $match: { status: 'active', tenantId: tenantObjId } },
      { $group: { _id: '$department', employees: { $sum: 1 } } },
      {
        $lookup: {
          from: 'departments',
          localField: '_id',
          foreignField: '_id',
          as: 'dept',
        },
      },
      { $unwind: { path: '$dept', preserveNullAndEmpty: true } },
      {
        $project: {
          department: { $ifNull: ['$dept.name', 'Unknown'] },
          employees: 1,
        },
      },
      { $sort: { employees: -1 } },
    ]);

    const leaveByDept = await Leave.aggregate([
      { $match: { tenantId: tenantObjId } },
      { $group: { _id: '$department', leaves: { $sum: 1 } } },
      {
        $lookup: {
          from: 'departments',
          localField: '_id',
          foreignField: '_id',
          as: 'dept',
        },
      },
      { $unwind: { path: '$dept', preserveNullAndEmpty: true } },
      { $project: { department: { $ifNull: ['$dept.name', 'Unknown'] }, leaves: 1 } },
    ]);

    const leaveMap = {};
    leaveByDept.forEach((d) => { leaveMap[d.department] = d.leaves; });

    const result = empByDept.map((d) => ({
      department: d.department,
      employees: d.employees,
      leaves: leaveMap[d.department] || 0,
    }));

    res.json(result);
  } catch (err) {
    console.error('getDepartmentAnalytics:', err);
    res.status(500).json({ message: 'Server error' });
  }
};
