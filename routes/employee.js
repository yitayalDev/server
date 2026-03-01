const router = require('express').Router();
const controller = require('../controllers/employeeController');
const { protect, authorize, checkPermission, authorizeOrPermission } = require('../middleware/authMiddleware');
const multer = require('multer');
const path = require('path');

const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, path.join(__dirname, '../public/upload')),
    filename: (req, file, cb) => cb(null, Date.now() + '-' + file.originalname),
});
const upload = multer({ storage });

router.get('/ping', (req, res) => res.json({ message: 'Employee Route Active (Subfolder)', version: '1.3' }));
router.put('/:id/permissions', protect, authorize('admin'), controller.updatePermissions);

router.post('/', protect, authorizeOrPermission(['admin', 'hr'], 'manage_users'), upload.single('image'), controller.createEmployee);
router.get('/', protect, authorize('admin', 'hr', 'it_admin'), controller.getEmployees);
router.get('/:id', protect, authorize('admin', 'hr', 'it_admin', 'employee'), controller.getEmployee);
router.put('/:id', protect, authorizeOrPermission(['admin', 'hr'], 'manage_users'), upload.single('image'), controller.updateEmployee);
router.delete('/:id', protect, authorizeOrPermission(['admin', 'it_admin'], 'delete_records'), controller.deleteEmployee);

module.exports = router;
