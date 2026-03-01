const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema({
  tenantId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }, // Root admins have no tenantId (or it's themselves)
  name: String,
  email: { type: String, unique: true },
  password: String,
  role: {
    type: String,
    enum: ['admin', 'employee', 'hr', 'finance', 'it_admin'],
    default: 'employee'
  },
  permissions: [{ type: String }],
  employee: { type: mongoose.Schema.Types.ObjectId, ref: 'Employee' },

  // 🔹 Added ONLY for reset password
  resetPasswordToken: String,
  resetPasswordExpire: Date,

  // 🔹 Custom Branding (for Admins/Tenants)
  companyLogo: String,
  companyName: String,
});

userSchema.pre('save', async function () {
  if (!this.isModified('password')) return;
  this.password = await bcrypt.hash(this.password, 10);
});

userSchema.methods.matchPassword = function (pass) {
  return bcrypt.compare(pass, this.password);
};

module.exports = mongoose.model('User', userSchema);
