const jwt = require('jsonwebtoken');
const User = require('../models/user');

exports.protect = async (req, res, next) => {
    try {
        let token;

        if (
            req.headers.authorization &&
            req.headers.authorization.startsWith('Bearer')
        ) {
            token = req.headers.authorization.split(' ')[1];
        }

        if (!token) {
            return res.status(401).json({ message: 'Not authorized, no token' });
        }

        const decoded = jwt.verify(token, process.env.JWT_SECRET);

        const user = await User.findById(decoded.id)
            .select('-password')
            .populate('employee');

        if (!user) {
            return res.status(401).json({ message: 'User not found' });
        }

        // Inject Tenant Isolation ID
        if (user.role === 'admin') {
            user.tenantId = user._id; // The Admin is the root of the tenant
        } else if (!user.tenantId) {
            console.warn(`User ${user.email} missing tenantId`);
        }

        // Ensure tenantId is available as a string for easy use
        if (user.tenantId) {
            user.tenantId = user.tenantId.toString();
        }

        // 🔥 THIS FIX MAKES LEAVE WORK
        if (user.role === 'employee' && user.employee) {
            user.employeeId = user.employee._id;
        }

        req.user = user;
        next();
    } catch (err) {
        console.error('Auth error:', err);
        res.status(401).json({ message: 'Not authorized' });
    }
};

// 🔹 Block destructive actions for Demo Users
exports.restrictDemo = (req, res, next) => {
    if (req.user && req.user.isDemo) {
        // Block POST, PUT, DELETE for demo users
        if (['POST', 'PUT', 'DELETE'].includes(req.method)) {
            return res.status(403).json({
                message: 'Action restricted: You are in Demo Mode. Data changes are not allowed for security reasons.',
                isDemo: true
            });
        }
    }
    next();
};

exports.authorize = (...roles) => {
    return (req, res, next) => {
        // Admin always has access
        if (req.user.role === 'admin') return next();

        if (!roles.includes(req.user.role)) {
            return res.status(403).json({ message: 'Access denied: Insufficient role' });
        }
        next();
    };
};

exports.checkPermission = (permission) => {
    return (req, res, next) => {
        // Admin always has access
        if (req.user.role === 'admin') return next();

        // Check if user has the specific permission in their permissions array
        if (req.user.permissions && req.user.permissions.includes(permission)) {
            return next();
        }

        return res.status(403).json({ message: `Access denied: Missing permission [${permission}]` });
    };
};

exports.authorizeOrPermission = (roles, permission) => {
    return (req, res, next) => {
        if (req.user.role === 'admin') return next();

        if (roles && roles.includes(req.user.role)) return next();

        if (permission && req.user.permissions && req.user.permissions.includes(permission)) {
            return next();
        }

        return res.status(403).json({ message: `Access denied: Insufficient role and missing permission [${permission}]` });
    };
};
