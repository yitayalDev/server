const router = require('express').Router();
const {
    getDepartments,
    createDepartment,
    updateDepartment,
    deleteDepartment
} = require('../controllers/departmentController');
const { protect, authorize, authorizeOrPermission } = require('../middleware/authMiddleware');

// -------------------- Admin + Employee + HR + IT --------------------
router.get('/', protect, authorize('admin', 'employee', 'hr', 'it_admin'), getDepartments);

// -------------------- Admin + HR --------------------
router.post('/', protect, authorize('admin', 'hr'), createDepartment);
router.put('/:id', protect, authorize('admin', 'hr'), updateDepartment);
router.delete('/:id', protect, authorizeOrPermission(['admin', 'hr'], 'delete_records'), deleteDepartment);

module.exports = router;
