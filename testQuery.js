require('dotenv').config();
const mongoose = require('mongoose');
const User = require('./models/user');

const testQuery = async () => {
    try {
        const mongoURI = process.env.MONGO_URI || 'mongodb://localhost:27017/ems_db';
        await mongoose.connect(mongoURI);

        console.log('Connected to:', mongoose.connection.name);

        const role = 'admin';
        const user = await User.findOne({ role, isDemo: true });

        if (user) {
            console.log('SUCCESS: Found user:', user.email);
        } else {
            console.log('FAILURE: No user found for role: admin with isDemo: true');
            const anyAdmin = await User.findOne({ role });
            console.log('Any Admin found?', anyAdmin ? anyAdmin.email : 'None');
        }

        process.exit(0);
    } catch (err) {
        console.error(err);
        process.exit(1);
    }
};

testQuery();
