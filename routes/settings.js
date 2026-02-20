const router = require('express').Router();
const { changePassword, updateProfile } = require('../controllers/settingController');
const { protect } = require('../middleware/authMiddleware');

router.post('/change-password', protect, changePassword);
router.put('/update-profile', protect, updateProfile);

module.exports = router;
