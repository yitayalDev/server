require('dotenv').config();
const mongoose = require('mongoose');
const User = require('./models/user');

const checkDB = async () => {
    try {
        const mongoURI = process.env.MONGO_URI || 'mongodb://localhost:27017/ems_db';
        console.log('Using URI:', mongoURI);
        await mongoose.connect(mongoURI);
        console.log('Connected to DB');

        const demoUsers = await User.find({ isDemo: true });
        console.log('Total Demo Users found:', demoUsers.length);

        demoUsers.forEach(u => {
            console.log(`- Role: ${u.role}, Email: ${u.email}, isDemo: ${u.isDemo}`);
        });

        const allUsers = await User.find({}).limit(5);
        console.log('Sample of any 5 users:');
        allUsers.forEach(u => {
            console.log(`- Role: ${u.role}, Email: ${u.email}, isDemo: ${u.isDemo}`);
        });

        process.exit(0);
    } catch (err) {
        console.error('Error:', err);
        process.exit(1);
    }
};

checkDB();
