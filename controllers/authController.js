const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const User = require('../models/user');
const Employee = require('../models/employee');

// JWT token generator
const generateToken = (id, role) =>
  jwt.sign(
    { id, role },
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_EXPIRES_IN }
  );

// ---------------- LOGIN ----------------
exports.login = async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email }).populate('employee');

    if (!user || !(await user.matchPassword(password))) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const token = generateToken(user._id, user.role);

    res.json({
      token,
      user: {
        _id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
        employeeId: user.employee?._id || null,
      },
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ message: 'Server error' });
  }
};

// ---------------- CREATE EMPLOYEE (admin only) ----------------
exports.createEmployeeAccount = async (req, res) => {
  try {
    const { name, email, password, departmentId, dob, position } = req.body;

    if (!name || !email || !password || !departmentId || !dob || !position) {
      return res.status(400).json({ message: 'All fields are required' });
    }

    const exist = await User.findOne({ email });
    if (exist) return res.status(400).json({ message: 'Email already exists' });

    const user = new User({ name, email, password, role: 'employee' });
    await user.save();

    let imagePath = '';
    if (req.file) imagePath = `/upload/${req.file.filename}`;

    const employee = new Employee({
      user: user._id,
      name,
      email,
      department: departmentId,
      dob,
      position,
      image: imagePath,
    });
    await employee.save();

    user.employee = employee._id;
    await user.save();

    res.status(201).json({
      message: 'Employee account created',
      user,
      employee,
    });

  } catch (err) {
    console.error('Error creating employee:', err);
    res.status(500).json({ message: 'Server error', error: err.message });
  }
};

// ================= ADD ONLY BELOW =================

// ---------------- FORGOT PASSWORD ----------------
exports.forgotPassword = async (req, res) => {
  try {
    const { email } = req.body;

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    const token = crypto.randomBytes(20).toString('hex');

    user.resetPasswordToken =
      crypto.createHash('sha256').update(token).digest('hex');
    user.resetPasswordExpire = Date.now() + 15 * 60 * 1000; // 15 min

    await user.save();

    // ⚠️ Token returned for testing (later email)
    res.json({
      message: 'Reset token generated',
      token,
    });
  } catch (err) {
    console.error('Forgot password error:', err);
    res.status(500).json({ message: 'Server error' });
  }
};

// ---------------- RESET PASSWORD ----------------
exports.resetPassword = async (req, res) => {
  try {
    const hashedToken =
      crypto.createHash('sha256').update(req.params.token).digest('hex');

    const user = await User.findOne({
      resetPasswordToken: hashedToken,
      resetPasswordExpire: { $gt: Date.now() },
    });

    if (!user) {
      return res.status(400).json({ message: 'Invalid or expired token' });
    }

    user.password = req.body.password;
    user.resetPasswordToken = undefined;
    user.resetPasswordExpire = undefined;

    await user.save();

    res.json({ message: 'Password reset success' });
  } catch (err) {
    console.error('Reset password error:', err);
    res.status(500).json({ message: 'Server error' });
  }
};
