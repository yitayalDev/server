const Asset = require('../models/asset');

exports.getAssets = async (req, res) => {
    try {
        const assets = await Asset.find({ tenantId: req.user.tenantId })
            .populate('assignedTo', 'name');
        res.json(assets);
    } catch (err) {
        res.status(500).json({ message: 'Server error fetching assets' });
    }
};

exports.createAsset = async (req, res) => {
    try {
        const asset = await Asset.create({
            ...req.body,
            tenantId: req.user.tenantId
        });
        res.status(201).json(asset);
    } catch (err) {
        res.status(500).json({ message: 'Server error creating asset' });
    }
};

exports.updateAsset = async (req, res) => {
    try {
        const asset = await Asset.findOneAndUpdate(
            { _id: req.params.id, tenantId: req.user.tenantId },
            req.body,
            { new: true }
        );
        if (!asset) return res.status(404).json({ message: 'Asset not found' });
        res.json(asset);
    } catch (err) {
        res.status(500).json({ message: 'Server error updating asset' });
    }
};

exports.deleteAsset = async (req, res) => {
    try {
        const asset = await Asset.findOneAndDelete({ _id: req.params.id, tenantId: req.user.tenantId });
        if (!asset) return res.status(404).json({ message: 'Asset not found' });
        res.json({ message: 'Asset deleted' });
    } catch (err) {
        res.status(500).json({ message: 'Server error deleting asset' });
    }
};
