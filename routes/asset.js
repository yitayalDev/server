const router = require('express').Router();
const controller = require('../controllers/assetController');
const { authorize, authorizeOrPermission } = require('../middleware/authMiddleware');

router.get('/', controller.getAssets);
router.post('/', authorizeOrPermission(['admin'], 'manage_assets'), controller.createAsset);
router.put('/:id', authorizeOrPermission(['admin'], 'manage_assets'), controller.updateAsset);
router.delete('/:id', authorizeOrPermission(['admin'], 'manage_assets'), controller.deleteAsset);

module.exports = router;
