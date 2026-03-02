const mongoose = require('mongoose');

const assetSchema = new mongoose.Schema({
    tenantId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    name: { type: String, required: true },
    type: { type: String, required: true }, // e.g., Laptop, Keyboard, Phone
    serialNumber: { type: String, required: true },
    value: { type: Number },
    purchaseDate: { type: Date },
    assignedTo: { type: mongoose.Schema.Types.ObjectId, ref: 'Employee' },
    status: {
        type: String,
        enum: ['available', 'assigned', 'repair', 'retired'],
        default: 'available'
    },
    description: { type: String }
}, { timestamps: true });

module.exports = mongoose.model('Asset', assetSchema);
