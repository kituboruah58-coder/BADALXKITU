const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const bcrypt = require('bcryptjs');

const dbPath = path.join(__dirname, 'auth.db');
const DEFAULT_ADMIN_EMAIL = String(
    process.env.DEFAULT_ADMIN_EMAIL || process.env.ADMIN_EMAIL || 'kitu@gmail.com'
).trim().toLowerCase();
const DEFAULT_ADMIN_PASSWORD = String(
    process.env.DEFAULT_ADMIN_PASSWORD || process.env.ADMIN_PASSWORD || 'kitu123'
).trim();

function ensureDefaultAdmin() {
    if (!DEFAULT_ADMIN_EMAIL || !DEFAULT_ADMIN_PASSWORD) {
        console.warn('Default admin seed skipped: missing DEFAULT_ADMIN_EMAIL/DEFAULT_ADMIN_PASSWORD');
        return;
    }

    db.get('SELECT id FROM admins WHERE email = ?', [DEFAULT_ADMIN_EMAIL], async (checkErr, row) => {
        if (checkErr) {
            console.error('Error checking default admin:', checkErr);
            return;
        }
        if (row) {
            console.log(`Default admin exists: ${DEFAULT_ADMIN_EMAIL}`);
            return;
        }

        try {
            const hashedPassword = await bcrypt.hash(DEFAULT_ADMIN_PASSWORD, 10);
            db.run(
                'INSERT INTO admins (email, password) VALUES (?, ?)',
                [DEFAULT_ADMIN_EMAIL, hashedPassword],
                (insertErr) => {
                    if (insertErr) {
                        console.error('Error creating default admin:', insertErr);
                        return;
                    }
                    console.log(`Default admin created: ${DEFAULT_ADMIN_EMAIL}`);
                }
            );
        } catch (hashErr) {
            console.error('Error hashing default admin password:', hashErr);
        }
    });
}

const db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
        console.error('Error opening database:', err);
    } else {
        console.log('Connected to SQLite database');
        initializeDatabase();
    }
});

function initializeDatabase() {
    // Users table
    db.run(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            status TEXT DEFAULT 'active',
            streamer_lite INTEGER DEFAULT 0,
            streamer_pro INTEGER DEFAULT 0,
            streamer_max INTEGER DEFAULT 0,
            streamer_ultra INTEGER DEFAULT 0,
            expires_at DATETIME,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `, (err) => {
        if (err) console.error('Error creating users table:', err);
        else {
            console.log('Users table ready');
            // Migration for expires_at
            db.run(`ALTER TABLE users ADD COLUMN expires_at DATETIME`, (err) => {
                if (err && !err.message.includes('duplicate column name')) console.error('expires_at migration:', err);
            });
            // Add tier columns if they don't exist (migration)
            db.run(`ALTER TABLE users ADD COLUMN streamer_lite INTEGER DEFAULT 0`, (err) => {
                if (err && !err.message.includes('duplicate column name')) console.error('streamer_lite:', err);
            });
            db.run(`ALTER TABLE users ADD COLUMN streamer_pro INTEGER DEFAULT 0`, (err) => {
                if (err && !err.message.includes('duplicate column name')) console.error('streamer_pro:', err);
            });
            db.run(`ALTER TABLE users ADD COLUMN streamer_max INTEGER DEFAULT 0`, (err) => {
                if (err && !err.message.includes('duplicate column name')) console.error('streamer_max:', err);
            });
            db.run(`ALTER TABLE users ADD COLUMN streamer_ultra INTEGER DEFAULT 0`, (err) => {
                if (err && !err.message.includes('duplicate column name')) console.error('streamer_ultra:', err);
            });
            // IP/HWID tracking migration
            db.run(`ALTER TABLE users ADD COLUMN last_ip TEXT`, (err) => {
                if (err && !err.message.includes('duplicate column name')) console.error('last_ip migration:', err);
            });
            db.run(`ALTER TABLE users ADD COLUMN last_hwid TEXT`, (err) => {
                if (err && !err.message.includes('duplicate column name')) console.error('last_hwid migration:', err);
            });
            db.run(`ALTER TABLE users ADD COLUMN last_login DATETIME`, (err) => {
                if (err && !err.message.includes('duplicate column name')) console.error('last_login migration:', err);
            });
        }
    });

    // Admins table
    db.run(`
        CREATE TABLE IF NOT EXISTS admins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `, (err) => {
        if (err) console.error('Error creating admins table:', err);
        else {
            console.log('Admins table ready');
            ensureDefaultAdmin();
        }
    });

    // License keys table
    db.run(`
        CREATE TABLE IF NOT EXISTS licenses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            license_key TEXT UNIQUE NOT NULL,
            user_id INTEGER,
            status TEXT DEFAULT 'active',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            expires_at DATETIME,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    `, (err) => {
        if (err) console.error('Error creating licenses table:', err);
        else console.log('Licenses table ready');
    });

    // Sessions table
    db.run(`
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token TEXT UNIQUE NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            expires_at DATETIME,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    `, (err) => {
        if (err) console.error('Error creating sessions table:', err);
        else console.log('Sessions table ready');
    });

    // EXE users table (separate credentials for Python launcher)
    db.run(`
        CREATE TABLE IF NOT EXISTS exe_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            status TEXT DEFAULT 'active',
            linked_user_id INTEGER,
            last_ip TEXT,
            last_hwid TEXT,
            bound_hwid TEXT,
            hwid_enforced INTEGER DEFAULT 1,
            failed_attempts INTEGER DEFAULT 0,
            lock_until DATETIME,
            last_login DATETIME,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `, (err) => {
        if (err) console.error('Error creating exe_users table:', err);
        else console.log('EXE users table ready');
    });

    db.run(`ALTER TABLE exe_users ADD COLUMN linked_user_id INTEGER`, (err) => {
        if (err && !err.message.includes('duplicate column name')) console.error('exe_users linked_user_id migration:', err);
    });
    db.run(`ALTER TABLE exe_users ADD COLUMN bound_hwid TEXT`, (err) => {
        if (err && !err.message.includes('duplicate column name')) console.error('exe_users bound_hwid migration:', err);
    });
    db.run(`ALTER TABLE exe_users ADD COLUMN hwid_enforced INTEGER DEFAULT 1`, (err) => {
        if (err && !err.message.includes('duplicate column name')) console.error('exe_users hwid_enforced migration:', err);
    });
    db.run(`ALTER TABLE exe_users ADD COLUMN failed_attempts INTEGER DEFAULT 0`, (err) => {
        if (err && !err.message.includes('duplicate column name')) console.error('exe_users failed_attempts migration:', err);
    });
    db.run(`ALTER TABLE exe_users ADD COLUMN lock_until DATETIME`, (err) => {
        if (err && !err.message.includes('duplicate column name')) console.error('exe_users lock_until migration:', err);
    });
}

module.exports = db;
