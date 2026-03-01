const mongoose = require('mongoose');

const salarySchema = new mongoose.Schema(
  {
    tenantId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    employee: { type: mongoose.Schema.Types.ObjectId, ref: 'Employee', required: true },
    department: { type: mongoose.Schema.Types.ObjectId, ref: 'Department' },
    basic: { type: Number, required: true },
    allowance: { type: Number, default: 0 },
    deductions: { type: Number, default: 0 },
    netSalary: { type: Number, required: true },
    payDate: { type: Date, required: true }
  },
  { timestamps: true }
);

module.exports = mongoose.model('Salary', salarySchema);
