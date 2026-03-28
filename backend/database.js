const db = require('./database');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-this-in-production';
const ADMIN_JWT_SECRET = process.env.ADMIN_JWT_SECRET || 'admin-secret-key-change-this-in-production';
const ADMIN_JWT_EXPIRY = '7d';

// Generate admin JWT token
function generateAdminToken(adminId) {
    return jwt.sign({ adminId, role: 'admin' }, ADMIN_JWT_SECRET, { expiresIn: ADMIN_JWT_EXPIRY });
}

// Verify admin JWT token
function verifyAdminToken(token) {
    try {
        return jwt.verify(token, ADMIN_JWT_SECRET);
    } catch (err) {
        return null;
    }
}

// Admin login
async function adminLogin(email, password) {
    return new Promise((resolve, reject) => {
        db.get('SELECT * FROM admins WHERE email = ?', [email], async (err, admin) => {
            if (err) return reject(err);
            
            if (!admin) {
                return reject(new Error('Admin not found'));
            }

            const passwordMatch = await bcrypt.compare(password, admin.password);
            
            if (!passwordMatch) {
                return reject(new Error('Invalid password'));
            }

            const token = generateAdminToken(admin.id);
            
            resolve({
                id: admin.id,
                email: admin.email,
                token
            });
        });
    });
}

// Get all users
function getAllUsers() {
    return new Promise((resolve, reject) => {
        db.all('SELECT id, username, email, status, created_at, updated_at, expires_at, last_ip, last_hwid, last_login FROM users ORDER BY created_at DESC', [], (err, users) => {
            if (err) return reject(err);
            resolve(users || []);
        });
    });
}

// Get active users with tiers
function getActiveUsers() {
    return new Promise((resolve, reject) => {
        db.all(`
            SELECT id, username, email, status, created_at, last_ip, last_hwid, last_login,
                   streamer_lite, streamer_pro, streamer_max, streamer_ultra 
            FROM users WHERE status = 'active' ORDER BY created_at DESC
        `, [], (err, users) => {
            if (err) return reject(err);
            resolve(users || []);
        });
    });
}

// Get user tiers
function getUserTiers(userId) {
    return new Promise((resolve, reject) => {
        db.get(`
            SELECT streamer_lite, streamer_pro, streamer_max, streamer_ultra 
            FROM users WHERE id = ?
        `, [userId], (err, user) => {
            if (err) return reject(err);
            if (!user) return reject(new Error('User not found'));
            resolve({
                streamer_lite: !!user.streamer_lite,
                streamer_pro: !!user.streamer_pro,
                streamer_max: !!user.streamer_max,
                streamer_ultra: !!user.streamer_ultra
            });
        });
    });
}

// Update user tiers
function updateUserTiers(userId, tiers) {
    return new Promise((resolve, reject) => {
        const { streamer_lite, streamer_pro, streamer_max, streamer_ultra } = tiers;
        db.run(`
            UPDATE users SET 
                streamer_lite = ?, streamer_pro = ?, streamer_max = ?, streamer_ultra = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        `, [streamer_lite ? 1 : 0, streamer_pro ? 1 : 0, streamer_max ? 1 : 0, streamer_ultra ? 1 : 0, userId], function(err) {
            if (err) return reject(err);
            if (this.changes === 0) return reject(new Error('User not found'));
            resolve({ message: 'User tiers updated successfully', userId });
        });
    });
}

// Get user by ID
function getUserById(userId) {
    return new Promise((resolve, reject) => {
        db.get('SELECT id, username, email, status, created_at, updated_at, expires_at FROM users WHERE id = ?', [userId], (err, user) => {
            if (err) return reject(err);
            if (!user) return reject(new Error('User not found'));
            resolve(user);
        });
    });
}

// Create new user
async function createUser(username, email, password, expires_at) {
    return new Promise((resolve, reject) => {
        db.get('SELECT * FROM users WHERE email = ? OR username = ?', [email, username], async (err, row) => {
            if (err) return reject(err);
            
            if (row) {
                return reject(new Error('Email or username already exists'));
            }

            const hashedPassword = await bcrypt.hash(password, 10);
            
            db.run(
                'INSERT INTO users (username, email, password, status, expires_at) VALUES (?, ?, ?, ?, ?)',
                [username, email, hashedPassword, 'active', expires_at || null],
                function(err) {
                    if (err) return reject(err);
                    
                    resolve({
                        id: this.lastID,
                        username,
                        email,
                        status: 'active',
                        expires_at: expires_at,
                        created_at: new Date().toISOString()
                    });
                }
            );
        });
    });
}

// Block user
function blockUser(userId) {
    return new Promise((resolve, reject) => {
        db.run(
            'UPDATE users SET status = ? WHERE id = ?',
            ['blocked', userId],
            function(err) {
                if (err) return reject(err);
                if (this.changes === 0) return reject(new Error('User not found'));
                
                resolve({ message: 'User blocked successfully', userId });
            }
        );
    });
}

// Unblock user
function unblockUser(userId) {
    return new Promise((resolve, reject) => {
        db.run(
            'UPDATE users SET status = ? WHERE id = ?',
            ['active', userId],
            function(err) {
                if (err) return reject(err);
                if (this.changes === 0) return reject(new Error('User not found'));
                
                resolve({ message: 'User unblocked successfully', userId });
            }
        );
    });
}

// Delete user
function deleteUser(userId) {
    return new Promise((resolve, reject) => {
        // Delete sessions first
        db.run('DELETE FROM sessions WHERE user_id = ?', [userId], (err) => {
            if (err) return reject(err);
            
            // Delete licenses linked to this user
            db.run('DELETE FROM licenses WHERE user_id = ?', [userId], (err) => {
                if (err) return reject(err);
                
                // Delete user
                db.run('DELETE FROM users WHERE id = ?', [userId], function(err) {
                    if (err) return reject(err);
                    if (this.changes === 0) return reject(new Error('User not found'));
                    
                    resolve({ message: 'User deleted successfully', userId });
                });
            });
        });
    });
}

// Get all EXE users
function getAllExeUsers() {
    return new Promise((resolve, reject) => {
        db.all(`
            SELECT 
                e.id,
                e.username,
                e.status,
                e.linked_user_id,
                e.last_ip,
                e.last_hwid,
                e.bound_hwid,
                e.hwid_enforced,
                e.failed_attempts,
                e.lock_until,
                e.last_login,
                e.created_at,
                e.updated_at,
                u.username AS linked_username,
                u.email AS linked_email
            FROM exe_users e
            LEFT JOIN users u ON u.id = e.linked_user_id
            ORDER BY e.created_at DESC
        `, [], (err, users) => {
            if (err) return reject(err);
            resolve(users || []);
        });
    });
}

// Create EXE user
async function createExeUser(username, password, linkedUserId = null) {
    return new Promise((resolve, reject) => {
        const normalizedUsername = String(username || '').trim();
        if (!normalizedUsername) {
            return reject(new Error('EXE username is required'));
        }

        db.get(
            'SELECT id FROM exe_users WHERE LOWER(TRIM(username)) = LOWER(TRIM(?))',
            [normalizedUsername],
            async (err, row) => {
            if (err) return reject(err);
            if (row) return reject(new Error('EXE username already exists'));

            const hashedPassword = await bcrypt.hash(password, 10);
            db.run(
                'INSERT INTO exe_users (username, password, status, linked_user_id) VALUES (?, ?, ?, ?)',
                [normalizedUsername, hashedPassword, 'active', linkedUserId || null],
                function(insertErr) {
                    if (insertErr) return reject(insertErr);
                    resolve({
                        id: this.lastID,
                        username: normalizedUsername,
                        linked_user_id: linkedUserId || null,
                        status: 'active',
                        created_at: new Date().toISOString()
                    });
                }
            );
            }
        );
    });
}

// Block EXE user
function blockExeUser(userId) {
    return new Promise((resolve, reject) => {
        db.run(
            'UPDATE exe_users SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
            ['blocked', userId],
            function(err) {
                if (err) return reject(err);
                if (this.changes === 0) return reject(new Error('EXE user not found'));
                resolve({ message: 'EXE user blocked successfully', userId });
            }
        );
    });
}

// Unblock EXE user
function unblockExeUser(userId) {
    return new Promise((resolve, reject) => {
        db.run(
            'UPDATE exe_users SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
            ['active', userId],
            function(err) {
                if (err) return reject(err);
                if (this.changes === 0) return reject(new Error('EXE user not found'));
                resolve({ message: 'EXE user unblocked successfully', userId });
            }
        );
    });
}

// Delete EXE user
function deleteExeUser(userId) {
    return new Promise((resolve, reject) => {
        db.run('DELETE FROM exe_users WHERE id = ?', [userId], function(err) {
            if (err) return reject(err);
            if (this.changes === 0) return reject(new Error('EXE user not found'));
            resolve({ message: 'EXE user deleted successfully', userId });
        });
    });
}

// Generate random license key
function generateLicenseKey() {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    let key = '';
    for (let i = 0; i < 4; i++) {
        for (let j = 0; j < 4; j++) {
            key += chars.charAt(Math.floor(Math.random() * chars.length));
        }
        if (i < 3) key += '-';
    }
    return key;
}

// Create new license key
function createLicenseKey(quantity = 1) {
    return new Promise((resolve, reject) => {
        const licenses = [];
        let completed = 0;

        for (let i = 0; i < quantity; i++) {
            const licenseKey = generateLicenseKey();
            
            db.run(
                'INSERT INTO licenses (license_key, status) VALUES (?, ?)',
                [licenseKey, 'active'],
                function(err) {
                    completed++;
                    if (err) {
                        console.error('Error creating license:', err);
                    } else {
                        licenses.push({
                            id: this.lastID,
                            license_key: licenseKey,
                            status: 'active',
                            created_at: new Date().toISOString()
                        });
                    }
                    
                    if (completed === quantity) {
                        if (licenses.length === 0) {
                            reject(new Error('Failed to create license keys'));
                        } else {
                            resolve(licenses);
                        }
                    }
                }
            );
        }
    });
}

// Get all licenses with user details
function getAllLicenses() {
    return new Promise((resolve, reject) => {
        db.all(`
            SELECT 
                l.id,
                l.license_key,
                l.status,
                l.created_at,
                u.email,
                u.password,
                u.username,
                u.created_at as used_date
            FROM licenses l
            LEFT JOIN users u ON l.user_id = u.id
            ORDER BY l.created_at DESC
        `, [], (err, licenses) => {
            if (err) return reject(err);
            resolve(licenses || []);
        });
    });
}

// Get user statistics
function getUserStatistics() {
    return new Promise((resolve, reject) => {
        db.all(`
            SELECT 
                COUNT(*) as total,
                SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END) as active,
                SUM(CASE WHEN status = 'blocked' THEN 1 ELSE 0 END) as blocked
            FROM users
        `, [], (err, result) => {
            if (err) return reject(err);
            resolve(result[0] || { total: 0, active: 0, blocked: 0 });
        });
    });
}

module.exports = {
    generateAdminToken,
    verifyAdminToken,
    adminLogin,
    getAllUsers,
    getActiveUsers,
    getUserTiers,
    updateUserTiers,
    getUserById,
    createUser,
    blockUser,
    unblockUser,
    deleteUser,
    getAllExeUsers,
    createExeUser,
    blockExeUser,
    unblockExeUser,
    deleteExeUser,
    getUserStatistics,
    generateLicenseKey,
    createLicenseKey,
    getAllLicenses
};

