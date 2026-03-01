const mongoose = require('mongoose');

const leaveSchema = new mongoose.Schema(
  {
    tenantId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    employee: { type: mongoose.Schema.Types.ObjectId, ref: 'Employee', required: true },
    department: { type: mongoose.Schema.Types.ObjectId, ref: 'Department' },
    leaveType: { type: String, required: true },
    days: { type: Number, required: true },
    fromDate: { type: Date },
    toDate: { type: Date },
    status: {
      type: String,
      enum: ['pending', 'approved', 'rejected'],
      default: 'pending'
    },
    reason: { type: String },
    file: { type: String }, // Added to store attachment filename
    seen: { type: Boolean, default: false } // Added to track if employee saw the status update
  },
  { timestamps: true }
);

module.exports = mongoose.model('Leave', leaveSchema);