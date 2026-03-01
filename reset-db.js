// reset-db.js
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

async function resetDatabase() {
    try {
        await mongoose.connect('mongodb://localhost:27017/ems_db');
        console.log('✅ Connected to MongoDB');
        
        // Clear users collection
        await mongoose.connection.db.collection('users').deleteMany({});
        console.log('🗑️  Cleared users collection');
        
        // Create a KNOWN admin user with PROPER hash
        const salt = await bcrypt.genSalt(10);
        const password = 'admin123';
        const hash = await bcrypt.hash(password, 10);
        
        await mongoose.connection.db.collection('users').insertOne({
            _id: new mongoose.Types.ObjectId(),
            employeeId: 'ADM001',
            username: 'admin',
            email: 'admin@example.com',
            password: hash, // REAL bcrypt hash
            role: 'admin',
            isActive: true,
            lastLogin: new Date(),
            createdAt: new Date(),
            updatedAt: new Date(),
            __v: 0
        });
        
        console.log('✅ Created admin user with KNOWN hash');
        console.log('🔐 Email: admin@example.com');
        console.log('🔐 Password: admin123');
        console.log('🔐 Hash:', hash);
        
        // Verify
        const users = await mongoose.connection.db.collection('users').find().toArray();
        console.log('\n📋 Users in database:', users.length);
        
        mongoose.connection.close();
        
    } catch (error) {
        console.error('❌ Error:', error);
    }
}

resetDatabase();