const User = require('../models/user');

exports.changePassword = async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    const user = await User.findById(req.user._id);

    if (!user || !(await user.matchPassword(currentPassword))) {
      return res.status(400).json({ message: 'Current password is incorrect' });
    }

    user.password = newPassword;
    await user.save();

    res.json({ message: 'Password changed successfully' });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
};

exports.getBranding = async (req, res) => {
  try {
    const user = await User.findById(req.user._id).select('companyLogo companyName');
    res.json(user);
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
};

exports.updateBranding = async (req, res) => {
  try {
    const { companyName } = req.body;
    const update = {};
    if (companyName) update.companyName = companyName;
    if (req.file) update.companyLogo = `/upload/${req.file.filename}`;

    const user = await User.findByIdAndUpdate(
      req.user._id,
      { $set: update },
      { new: true }
    ).select('companyLogo companyName');

    res.json({ message: 'Branding updated successfully', settings: user });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
};
