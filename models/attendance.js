const mongoose = require('mongoose');

const attendanceSchema = new mongoose.Schema({
    tenantId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    employee: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Employee',
        required: true,
    },
    date: {
        type: String, // stored as 'YYYY-MM-DD' for easy daily lookup
        required: true,
    },
    checkIn: {
        type: Date,
    },
    checkOut: {
        type: Date,
    },
    status: {
        type: String,
        enum: ['present', 'late', 'absent'],
        default: 'absent',
    },
    ipAddress: {
        type: String,
    },
    location: {
        lat: { type: Number },
        lng: { type: Number },
    },
    workHours: {
        type: Number, // hours, e.g. 7.5
        default: 0,
    },
}, { timestamps: true });

// Ensure one record per employee per day
attendanceSchema.index({ employee: 1, date: 1 }, { unique: true });

module.exports = mongoose.model('Attendance', attendanceSchema);
