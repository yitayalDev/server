const Employee = require('../models/employee');
const User = require('../models/user');
const bcrypt = require('bcryptjs');

// CREATE EMPLOYEE (Admin only)
const createEmployee = async (req, res) => {
    try {
        const { name, email, password, dob, joinDate, departmentId, position, status } = req.body;

        if (!name || !email || !password || !dob || !departmentId || !position) {
            return res.status(400).json({ message: 'All fields are required' });
        }

        const existingUser = await User.findOne({ email });
        if (existingUser) return res.status(400).json({ message: 'Email already exists' });

        const hashedPassword = await bcrypt.hash(password, 10);

        const user = new User({
            name,
            email,
            password: hashedPassword,
            role: 'employee',
            tenantId: req.user.tenantId
        });
        await user.save();

        let imagePath = '';
        if (req.file) imagePath = `/upload/${req.file.filename}`;

        const employee = new Employee({
            user: user._id,
            name,
            email,
            password: hashedPassword,
            dob,
            joinDate: joinDate || new Date(),
            department: departmentId,
            position,
            status: status || 'active',
            image: imagePath,
            tenantId: req.user.tenantId
        });
        await employee.save();

        user.employee = employee._id;
        await user.save();

        res.status(201).json({ message: 'Employee created successfully', user, employee });
    } catch (err) {
        console.error('Error creating employee:', err);
        res.status(500).json({ message: 'Server error', error: err.message });
    }
};

const getEmployees = async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 10;
        const skip = (page - 1) * limit;

        const query = { tenantId: req.user.tenantId };
        const total = await Employee.countDocuments(query);
        const employees = await Employee.find(query)
            .populate('department')
            .populate('user')
            .skip(skip)
            .limit(limit);

        res.json({
            employees,
            total,
            page,
            pages: Math.ceil(total / limit)
        });
    } catch (err) {
        console.error('Error fetching employees:', err);
        res.status(500).json({ message: 'Server error', error: err.message });
    }
};

const getEmployee = async (req, res) => {
    try {
        const { id } = req.params;
        // 🔹 Guard against route shadowing
        if (id === 'ping' || id === 'permissions') return;

        const employee = await Employee.findOne({ _id: id, tenantId: req.user.tenantId })
            .populate('department', 'name')
            .populate('user', 'email role permissions');

        if (!employee) return res.status(404).json({ message: 'Employee not found', v: '1.4' });
        res.status(200).json(employee);
    } catch (err) {
        console.error('getEmployee error:', err);
        res.status(500).json({ message: 'Server error', error: err.message, v: '1.4' });
    }
};

const updateEmployee = async (req, res) => {
    try {
        const employee = await Employee.findOne({ _id: req.params.id, tenantId: req.user.tenantId });
        if (!employee) return res.status(404).json({ message: 'Employee not found' });

        const { name, email, password, dob, joinDate, departmentId, position, status } = req.body;

        if (name) employee.name = name.trim();
        if (email) employee.email = email.trim().toLowerCase();
        if (dob) employee.dob = dob;
        if (joinDate) employee.joinDate = joinDate;
        if (departmentId) employee.department = departmentId;
        if (position) employee.position = position.trim();
        if (status) employee.status = status;

        if (password && password.trim() !== '') {
            const hashedPassword = await bcrypt.hash(password, 10);
            employee.password = hashedPassword;

            const user = await User.findById(employee.user);
            if (user) {
                user.password = hashedPassword;
                await user.save();
            }
        }

        if (req.file) employee.image = `/upload/${req.file.filename}`;

        await employee.save();
        res.json({ message: 'Employee updated successfully', employee });
    } catch (err) {
        console.error('Error updating employee:', err);
        res.status(500).json({ message: 'Server error', error: err.message });
    }
};

const deleteEmployee = async (req, res) => {
    try {
        const employee = await Employee.findOne({ _id: req.params.id, tenantId: req.user.tenantId });
        if (!employee) return res.status(404).json({ message: 'Employee not found' });

        await User.findByIdAndDelete(employee.user);
        await employee.deleteOne();
        res.json({ message: 'Employee deleted successfully' });
    } catch (err) {
        console.error('Error deleting employee:', err);
        res.status(500).json({ message: 'Server error', error: err.message });
    }
};

const updatePermissions = async (req, res) => {
    try {
        const employee = await Employee.findOne({ _id: req.params.id, tenantId: req.user.tenantId });
        if (!employee) return res.status(404).json({ message: 'Employee not found' });

        const user = await User.findById(employee.user);
        if (!user) return res.status(404).json({ message: 'User not found' });

        const { role, permissions } = req.body;
        if (role) user.role = role;
        if (permissions) user.permissions = permissions;

        await user.save();
        res.json({ message: 'Permissions updated successfully', user, employee });
    } catch (err) {
        console.error('Error updating permissions:', err);
        res.status(500).json({ message: 'Server error', error: err.message });
    }
};

module.exports = {
    createEmployee,
    getEmployees,
    getEmployee,
    updateEmployee,
    deleteEmployee,
    updatePermissions,
};
