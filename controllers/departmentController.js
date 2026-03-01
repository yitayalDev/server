const Department = require('../models/department');

exports.getDepartments = async (req, res) => {
  try {
    const departments = await Department.find({ tenantId: req.user.tenantId }).sort({ createdAt: -1 });
    res.json(departments);
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
};

exports.createDepartment = async (req, res) => {
  try {
    const { name } = req.body;
    const exists = await Department.findOne({ name, tenantId: req.user.tenantId });
    if (exists) return res.status(400).json({ message: 'Department already exists' });

    const department = await Department.create({
      name,
      tenantId: req.user.tenantId
    });
    res.status(201).json(department);
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
};

exports.updateDepartment = async (req, res) => {
  try {
    const { id } = req.params;
    const { name } = req.body;
    const department = await Department.findByIdAndUpdate(
      id,
      { name },
      { new: true }
    );
    if (!department) return res.status(404).json({ message: 'Not found' });
    res.json(department);
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
};

exports.deleteDepartment = async (req, res) => {
  try {
    const { id } = req.params;
    await Department.findOneAndDelete({ _id: id, tenantId: req.user.tenantId });
    res.json({ message: 'Department deleted' });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
};
