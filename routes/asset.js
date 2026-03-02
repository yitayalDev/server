const router = require('express').Router();
const controller = require('../controllers/assetController');
const { authorize } = require('../middleware/authMiddleware');

router.get('/', controller.getAssets);
router.post('/', authorize('admin', 'hr'), controller.createAsset);
router.put('/:id', authorize('admin', 'hr'), controller.updateAsset);
router.delete('/:id', authorize('admin'), controller.deleteAsset);

module.exports = router;
