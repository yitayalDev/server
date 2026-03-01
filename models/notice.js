const mongoose = require('mongoose');

const noticeSchema = new mongoose.Schema({
    tenantId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    title: { type: String, required: true },
    content: { type: String, required: true },
    createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    isImportant: { type: Boolean, default: false }
}, { timestamps: true });

module.exports = mongoose.model('Notice', noticeSchema);
