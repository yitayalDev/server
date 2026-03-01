const Leave = require('../models/leave');

exports.getLeaves = async (req, res) => {
  try {
    const leaves = await Leave.find({ tenantId: req.user.tenantId })
      .populate({
        path: 'employee',
        select: 'name email position'
      })
      .populate({
        path: 'department',
        select: 'name'
      })
      .sort({ createdAt: -1 });

    res.json(leaves);
  } catch (err) {
    console.error('Get leaves error:', err);
    res.status(500).json({ message: 'Server error' });
  }
};

exports.requestLeave = async (req, res) => {
  try {
    const { departmentId, leaveType, days, fromDate, toDate, reason } = req.body;

    const leave = await Leave.create({
      tenantId: req.user.tenantId,

      // ✅ IMPORTANT FIX
      employee: req.user.employeeId,

      department: departmentId || null,
      leaveType,
      days: Number(days),
      fromDate,
      toDate,
      reason,
      file: req.file ? req.file.filename : null,
      status: 'pending',

      // ✅ IMPORTANT FIX
      seen: false
    });

    res.status(201).json({ message: 'Submitted successfully', leave });
  } catch (err) {
    console.error('Request leave error:', err);
    res.status(500).json({ message: 'Submission failed' });
  }
};

exports.updateLeaveStatus = async (req, res) => {
  try {
    const { status } = req.body;

    const leave = await Leave.findOneAndUpdate(
      { _id: req.params.id, tenantId: req.user.tenantId },
      {
        status,
        seen: false
      },
      { new: true }
    );

    if (!leave) {
      return res.status(404).json({ message: 'Not found' });
    }

    res.json(leave);
  } catch (err) {
    console.error('Update leave error:', err);
    res.status(500).json({ message: 'Update failed' });
  }
};
