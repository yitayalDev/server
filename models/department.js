const mongoose = require('mongoose');

const departmentSchema = new mongoose.Schema(
  {
    tenantId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    name: { type: String, required: true } // Removed global unique constraint to allow same department names across companies
  },
  { timestamps: true }
);

module.exports = mongoose.model('Department', departmentSchema);
