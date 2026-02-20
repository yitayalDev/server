const router = require('express').Router();
const {
  login,
  createEmployeeAccount,
  forgotPassword,
  resetPassword,
  updatePassword, // optional if you want a logged-in user to change password
} = require('../controllers/authController');

const { protect, authorize } = require('../middleware/authMiddleware');
const upload = require('../middleware/upload');

// Auth routes
router.post('/login', login);

// Forgot / Reset Password
router.post('/forgot-password', forgotPassword); // generates token, emails user
router.post('/reset-password/:token', resetPassword); // uses token to reset

// Optional: logged-in user password update
// router.put('/update-password', protect, updatePassword);

router.post(
  '/create-employee',
  protect,
  authorize('admin'),
  upload.single('image'),
  createEmployeeAccount
);

module.exports = router;
