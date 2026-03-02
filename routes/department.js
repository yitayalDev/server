const router = require('express').Router();
const {
    getDepartments,
    createDepartment,
    updateDepartment,
    deleteDepartment
} = require('../controllers/departmentController');
const { protect, authorize, authorizeOrPermission } = require('../middleware/authMiddleware');

// -------------------- All Auth Users (View) --------------------
router.get('/', protect, getDepartments);

// -------------------- Restricted (Manage) --------------------
router.post('/', protect, authorizeOrPermission(['admin'], 'manage_departments'), createDepartment);
router.put('/:id', protect, authorizeOrPermission(['admin'], 'manage_departments'), updateDepartment);
router.delete('/:id', protect, authorizeOrPermission(['admin'], 'manage_departments'), deleteDepartment);

module.exports = router;
