const router = require('express').Router();
const { changePassword, getBranding, updateBranding } = require('../controllers/settingController');
const { protect, authorize } = require('../middleware/authMiddleware');
const upload = require('../middleware/upload');

router.post('/change-password', protect, changePassword);
router.get('/branding', protect, authorize('admin'), getBranding);
router.put('/branding', protect, authorize('admin'), upload.single('logo'), updateBranding);

module.exports = router;
