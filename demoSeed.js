require('dotenv').config();
const mongoose = require('mongoose');
const connectDB = require('./config/db');
const User = require('./models/user');
const { getPermissionsForRole } = require('./utils/permissionConfig');

const seedDemoUsers = async () => {
    try {
        const mongoURI = process.env.MONGO_URI || 'mongodb://localhost:27017/ems_db';
        await mongoose.connect(mongoURI);

        const demoRoles = ['admin', 'employee', 'hr', 'finance', 'it_admin'];

        for (const role of demoRoles) {
            const email = `demo_${role}@example.com`;
            const existing = await User.findOne({ email });

            if (existing) {
                console.log(`Demo user for ${role} already exists: ${email}`);
                // Ensure isDemo is set
                if (!existing.isDemo) {
                    existing.isDemo = true;
                    await existing.save();
                    console.log(`Updated existing user to demo: ${email}`);
                }
                continue;
            }

            const name = `Demo ${role.toUpperCase().replace('_', ' ')}`;
            const user = new User({
                name,
                email,
                password: 'demo123', // Standard demo password
                role,
                isDemo: true,
                permissions: getPermissionsForRole(role),
                companyName: 'Demo Corp',
            });

            await user.save();
            console.log(`Created demo user: ${email} / demo123`);
        }

        console.log('Demo seeder completed successfully.');
        process.exit(0);
    } catch (err) {
        console.error('Demo seeder error:', err);
        process.exit(1);
    }
};

seedDemoUsers();
