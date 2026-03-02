const Notice = require('../models/notice');
const Employee = require('../models/employee');
const { sendNotification } = require('./notificationController');

const getNotices = async (req, res) => {
    try {
        const notices = await Notice.find({ tenantId: req.user.tenantId })
            .populate('createdBy', 'name')
            .sort({ createdAt: -1 });
        res.json(notices);
    } catch (error) {
        res.status(500).json({ message: 'Error fetching notices' });
    }
};

const createNotice = async (req, res) => {
    try {
        const { title, content, isImportant } = req.body;
        const newNotice = new Notice({
            tenantId: req.user.tenantId,
            createdBy: req.user._id,
            title,
            content,
            isImportant
        });
        const saved = await newNotice.save();

        // Notify all employees in the tenant
        const employees = await Employee.find({ tenantId: req.user.tenantId }).select('user');
        for (const emp of employees) {
            if (emp.user && emp.user.toString() !== req.user._id.toString()) {
                await sendNotification({
                    tenantId: req.user.tenantId,
                    recipient: emp.user,
                    message: `New Notice: ${title}`,
                    type: isImportant ? 'warning' : 'info',
                    link: '/admin/notices' // Or employee equivalent
                });
            }
        }

        res.status(201).json(saved);
    } catch (error) {
        res.status(500).json({ message: 'Error creating notice' });
    }
};

const deleteNotice = async (req, res) => {
    try {
        const { id } = req.params;
        const notice = await Notice.findOne({ _id: id, tenantId: req.user.tenantId });
        if (!notice) return res.status(404).json({ message: 'Notice not found' });

        await Notice.findOneAndDelete({ _id: id, tenantId: req.user.tenantId });
        res.json({ message: 'Notice deleted' });
    } catch (error) {
        res.status(500).json({ message: 'Error deleting notice' });
    }
};

module.exports = { getNotices, createNotice, deleteNotice };
