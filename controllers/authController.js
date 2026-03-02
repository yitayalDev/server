const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const User = require('../models/user');
const Employee = require('../models/employee');
const sendEmail = require('../utils/email');

// JWT token generator
const generateToken = (id, role) =>
  jwt.sign(
    { id, role },
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_EXPIRES_IN || '7d' }
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

    // For employees, we want to return their tenant's branding
    let branding = { logo: user.companyLogo, name: user.companyName };
    if (user.role === 'employee' && user.tenantId) {
      const admin = await User.findById(user.tenantId);
      if (admin) {
        branding.logo = admin.companyLogo;
        branding.name = admin.companyName;
      }
    }

    res.json({
      token,
      user: {
        _id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
        permissions: user.permissions || [],
        employeeId: user.employee?._id || null,
        companyLogo: branding.logo,
        companyName: branding.name,
      },
    });
  } catch (err) {
    console.error('Login error:', err.message, err.stack);
    res.status(500).json({ message: 'Server error', detail: err.message });
  }
};

// ---------------- REGISTER ADMIN (Org Signup) ----------------
exports.registerAdmin = async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({ message: 'All fields are required' });
    }

    const exist = await User.findOne({ email });
    if (exist) return res.status(400).json({ message: 'Email already exists' });

    // Ensure the new user is an admin without a parent tenantId (they are the root)
    const user = new User({
      name,
      email,
      password,
      role: 'admin',
      permissions: ['manage_users', 'manage_salary', 'manage_leaves', 'manage_departments'] // Give them all permissions by default
    });

    // Explicitly set tenantId to their own ID after creation, or simply let authMiddleware handle it
    // But setting it explicitly is cleaner for DB consistency
    await user.save();
    user.tenantId = user._id;
    await user.save();

    const token = generateToken(user._id, user.role);

    res.status(201).json({
      message: 'Organization created successfully',
      token,
      user: {
        _id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
        permissions: user.permissions
      },
    });

  } catch (err) {
    console.error('Register Admin error:', err);
    res.status(500).json({ message: 'Server error', error: err.message });
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

    const user = new User({
      name,
      email,
      password,
      role: 'employee',
      tenantId: req.user.tenantId
    });
    await user.save();

    let imagePath = '';
    if (req.file) imagePath = `/upload/${req.file.filename}`;

    const employee = new Employee({
      tenantId: req.user.tenantId,
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

    // Create reset url
    const resetUrl = `${process.env.CLIENT_URL}/reset-password/${token}`;

    const message = `You are receiving this email because you (or someone else) has requested the reset of a password. Please make a POST request to: \n\n ${resetUrl}`;

    try {
      await sendEmail({
        email: user.email,
        subject: 'Password reset token',
        message,
      });

      res.json({ message: 'Email sent successfully' });
    } catch (err) {
      console.error('Email sending failed:', err);
      user.resetPasswordToken = undefined;
      user.resetPasswordExpire = undefined;
      await user.save();

      return res.status(500).json({ message: 'Email could not be sent' });
    }
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
