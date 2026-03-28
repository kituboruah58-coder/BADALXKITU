const db = require('./backend/database');

setTimeout(() => {
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
}, 1000);
