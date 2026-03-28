const db = require('./backend/database');
const bcrypt = require('bcryptjs');

// Add test admin
setTimeout(async () => {
    try {
        const hashedPassword = await bcrypt.hash('kitu123', 10);
        db.run(
            "INSERT OR IGNORE INTO admins (email, password) VALUES (?, ?)",
            ['kitu@gmail.com', hashedPassword],
            (err) => {
                if (err) {
                    console.log('Admin exists or error:', err.message);
                } else {
                    console.log('✓ Admin account created successfully!');
                    console.log('  Email: kitu@gmail.com');
                    console.log('  Password: kitu123');
                    console.log('\n✓ Admin Dashboard: http://localhost:5001');
                }
                
                // Add test license
                db.run(
                    "INSERT OR IGNORE INTO licenses (license_key, status) VALUES (?, 'active')",
                    ['TEST-1234-5678-ABCD'],
                    (err) => {
                        if (err) {
                            console.log('License exists or error:', err.message);
                        } else {
                            console.log('✓ Test license added: TEST-1234-5678-ABCD');
                        }
                        process.exit(0);
                    }
                );
            }
        );
    } catch (error) {
        console.error('Error:', error.message);
        process.exit(1);
    }
}, 1000);
