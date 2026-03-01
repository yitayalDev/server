const Attendance = require('../models/attendance');
const Employee = require('../models/employee');
const moment = require('moment');

// ─── Helpers ────────────────────────────────────────────────────────────────

/**
 * Extract real client IP (supports X-Forwarded-For behind proxies / Render).
 */
const getClientIp = (req) => {
    const forwarded = req.headers['x-forwarded-for'];
    if (forwarded) return forwarded.split(',')[0].trim();
    return req.socket?.remoteAddress || req.ip || '';
};

/**
 * Haversine distance in km between two lat/lng points.
 */
const haversineKm = (lat1, lng1, lat2, lng2) => {
    const R = 6371;
    const dLat = ((lat2 - lat1) * Math.PI) / 180;
    const dLng = ((lng2 - lng1) * Math.PI) / 180;
    const a =
        Math.sin(dLat / 2) ** 2 +
        Math.cos((lat1 * Math.PI) / 180) *
        Math.cos((lat2 * Math.PI) / 180) *
        Math.sin(dLng / 2) ** 2;
    return R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
};

/**
 * Validate IP and geo restrictions.
 * Returns { allowed: true } or { allowed: false, reason: String }.
 */
const validateLocation = (req, lat, lng) => {
    // ── IP Restriction ──────────────────────────────────────────────────────
    const officeIps = process.env.OFFICE_IPS;
    if (officeIps) {
        const allowedIps = officeIps.split(',').map((s) => s.trim());
        const clientIp = getClientIp(req);
        if (!allowedIps.includes(clientIp)) {
            return {
                allowed: false,
                reason: `Check-in denied: your IP (${clientIp}) is not in the office network.`,
            };
        }
    }

    // ── Geo-fencing ─────────────────────────────────────────────────────────
    const officeLat = parseFloat(process.env.OFFICE_LAT);
    const officeLng = parseFloat(process.env.OFFICE_LNG);
    const officeRadius = parseFloat(process.env.OFFICE_RADIUS_KM || '0.1');

    if (officeLat && officeLng && lat != null && lng != null) {
        const dist = haversineKm(lat, lng, officeLat, officeLng);
        if (dist > officeRadius) {
            return {
                allowed: false,
                reason: `Check-in denied: you are ${dist.toFixed(2)} km from the office (allowed: ${officeRadius} km).`,
            };
        }
    }

    return { allowed: true };
};

/**
 * Determine attendance status based on check-in time.
 * "late" if after 09:15, otherwise "present".
 */
const deriveStatus = (checkInDate) => {
    const hour = checkInDate.getHours();
    const minute = checkInDate.getMinutes();
    const lateHour = parseInt(process.env.LATE_AFTER_HOUR || '9', 10);
    const lateMinute = parseInt(process.env.LATE_AFTER_MINUTE || '15', 10);
    return hour > lateHour || (hour === lateHour && minute >= lateMinute)
        ? 'late'
        : 'present';
};

// ─── Controllers ─────────────────────────────────────────────────────────────

/**
 * POST /api/attendance/check-in
 * Body: { lat?, lng? }
 */
exports.checkIn = async (req, res) => {
    try {
        const { lat, lng } = req.body;

        // Find the employee record linked to the logged-in user
        const employee = await Employee.findOne({ user: req.user._id });
        if (!employee) return res.status(404).json({ message: 'Employee profile not found.' });

        // Validate IP / geo
        const validation = validateLocation(req, lat, lng);
        if (!validation.allowed) return res.status(403).json({ message: validation.reason });

        const today = moment().format('YYYY-MM-DD');
        const existing = await Attendance.findOne({
            employee: employee._id,
            date: today,
            tenantId: req.user.tenantId
        });

        if (existing && existing.checkIn) {
            return res.status(400).json({ message: 'Already checked in today.' });
        }

        const now = new Date();
        const status = deriveStatus(now);
        const ip = getClientIp(req);

        const record = await Attendance.findOneAndUpdate(
            { employee: employee._id, date: today },
            {
                checkIn: now,
                status,
                ipAddress: ip,
                location: lat != null && lng != null ? { lat, lng } : undefined,
                tenantId: req.user.tenantId
            },
            { upsert: true, new: true, setDefaultsOnInsert: true }
        );

        res.status(200).json({ message: 'Checked in successfully.', record });
    } catch (err) {
        console.error('checkIn error:', err);
        res.status(500).json({ message: 'Server error during check-in.' });
    }
};

/**
 * POST /api/attendance/check-out
 */
exports.checkOut = async (req, res) => {
    try {
        const employee = await Employee.findOne({ user: req.user._id });
        if (!employee) return res.status(404).json({ message: 'Employee profile not found.' });

        const today = moment().format('YYYY-MM-DD');
        const record = await Attendance.findOne({
            employee: employee._id,
            date: today,
            tenantId: req.user.tenantId
        });

        if (!record || !record.checkIn) {
            return res.status(400).json({ message: 'No check-in found for today.' });
        }
        if (record.checkOut) {
            return res.status(400).json({ message: 'Already checked out today.' });
        }

        const now = new Date();
        const diffMs = now - record.checkIn;
        const workHours = parseFloat((diffMs / 3600000).toFixed(2));

        record.checkOut = now;
        record.workHours = workHours;
        await record.save();

        res.status(200).json({ message: 'Checked out successfully.', record });
    } catch (err) {
        console.error('checkOut error:', err);
        res.status(500).json({ message: 'Server error during check-out.' });
    }
};

/**
 * GET /api/attendance/today
 */
exports.getTodayStatus = async (req, res) => {
    try {
        const employee = await Employee.findOne({ user: req.user._id });
        if (!employee) return res.status(404).json({ message: 'Employee profile not found.' });

        const today = moment().format('YYYY-MM-DD');
        const record = await Attendance.findOne({
            employee: employee._id,
            date: today,
            tenantId: req.user.tenantId
        });

        res.status(200).json({ record: record || null });
    } catch (err) {
        console.error('getTodayStatus error:', err);
        res.status(500).json({ message: 'Server error.' });
    }
};

/**
 * GET /api/attendance/my?period=week|month&date=YYYY-MM-DD
 */
exports.getMyTimesheets = async (req, res) => {
    try {
        const employee = await Employee.findOne({ user: req.user._id });
        if (!employee) return res.status(404).json({ message: 'Employee profile not found.' });

        const { period = 'week', date } = req.query;
        const ref = date ? moment(date) : moment();

        let startDate, endDate;
        if (period === 'month') {
            startDate = ref.clone().startOf('month').format('YYYY-MM-DD');
            endDate = ref.clone().endOf('month').format('YYYY-MM-DD');
        } else {
            startDate = ref.clone().startOf('isoWeek').format('YYYY-MM-DD');
            endDate = ref.clone().endOf('isoWeek').format('YYYY-MM-DD');
        }

        const records = await Attendance.find({
            employee: employee._id,
            tenantId: req.user.tenantId,
            date: { $gte: startDate, $lte: endDate },
        }).sort({ date: 1 });

        const totalHours = records.reduce((s, r) => s + (r.workHours || 0), 0);
        const daysPresent = records.filter((r) => r.status !== 'absent').length;

        res.status(200).json({
            records,
            summary: {
                totalHours: parseFloat(totalHours.toFixed(2)),
                daysPresent,
                daysAbsent: records.filter((r) => r.status === 'absent').length,
                period,
                startDate,
                endDate,
            },
        });
    } catch (err) {
        console.error('getMyTimesheets error:', err);
        res.status(500).json({ message: 'Server error.' });
    }
};

/**
 * GET /api/attendance?employeeId=&date=&period=week|month
 * Admin only
 */
exports.getAllAttendance = async (req, res) => {
    try {
        const { employeeId, date, period = 'month', status } = req.query;
        const ref = date ? moment(date) : moment();

        let startDate, endDate;
        if (period === 'month') {
            startDate = ref.clone().startOf('month').format('YYYY-MM-DD');
            endDate = ref.clone().endOf('month').format('YYYY-MM-DD');
        } else {
            startDate = ref.clone().startOf('isoWeek').format('YYYY-MM-DD');
            endDate = ref.clone().endOf('isoWeek').format('YYYY-MM-DD');
        }

        const filter = {
            date: { $gte: startDate, $lte: endDate },
            tenantId: req.user.tenantId
        };
        if (employeeId) filter.employee = employeeId;
        if (status) filter.status = status;

        const records = await Attendance.find(filter)
            .populate({ path: 'employee', select: 'name email department', populate: { path: 'department', select: 'dep_name' } })
            .sort({ date: -1, 'employee.name': 1 });

        res.status(200).json({ records, startDate, endDate });
    } catch (err) {
        console.error('getAllAttendance error:', err);
        res.status(500).json({ message: 'Server error.' });
    }
};
