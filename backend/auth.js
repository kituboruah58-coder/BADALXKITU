const db = require('./database');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-this-in-production';
const JWT_EXPIRY = '7d';

// Helper function to hash password
async function hashPassword(password) {
    return bcrypt.hash(password, 10);
}

// Helper function to compare password
async function comparePassword(password, hash) {
    return bcrypt.compare(password, hash);
}

// Generate JWT token
function generateToken(userId) {
    return jwt.sign({ userId }, JWT_SECRET, { expiresIn: JWT_EXPIRY });
}

// Verify JWT token
function verifyToken(token) {
    try {
        return jwt.verify(token, JWT_SECRET);
    } catch (err) {
        return null;
    }
}

// Register user
async function registerUser(username, email, password) {
    return new Promise((resolve, reject) => {
        db.get('SELECT * FROM users WHERE email = ? OR username = ?', [email, username], async (err, row) => {
            if (err) return reject(err);
            
            if (row) {
                return reject(new Error('Email or username already exists'));
            }

            const hashedPassword = await hashPassword(password);
            
            db.run(
                'INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
                [username, email, hashedPassword],
                function(err) {
                    if (err) return reject(err);
                    
                    const token = generateToken(this.lastID);
                    resolve({
                        id: this.lastID,
                        username,
                        email,
                        token
                    });
                }
            );
        });
    });
}

// Login user
async function loginUser(email, password) {
    return new Promise((resolve, reject) => {
        db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
            if (err) return reject(err);
            
            if (!user) {
                return reject(new Error('User not found'));
            }

            // Check if account expired
            if (user.expires_at && new Date() > new Date(user.expires_at)) {
                return reject(new Error('Account expired. Contact admin for extension.'));
            }

            // Check if user is blocked
            if (user.status === 'blocked') {
                return reject(new Error('Your account has been blocked. Please contact support.'));
            }

            // Tier gating: require at least one streamer tier
            if (!user.streamer_lite && !user.streamer_pro && !user.streamer_max && !user.streamer_ultra) {
                return reject(new Error('Streamer tier required. Join our Discord: https://discord.gg/G54H6hpfrc'));
            }

            const passwordMatch = await comparePassword(password, user.password);
            
            if (!passwordMatch) {
                return reject(new Error('Invalid password'));
            }

            const token = generateToken(user.id);
            
            db.run(
                'INSERT INTO sessions (user_id, token, expires_at) VALUES (?, ?, datetime("now", "+7 days"))',
                [user.id, token],
                (err) => {
                    if (err) return reject(err);
                    
                    resolve({
                        id: user.id,
                        username: user.username,
                        email: user.email,
                        expires_at: user.expires_at,
                        token
                    });
                }
            );
        });
    });
}

// License registration
async function registerWithLicense(licenseKey, email, password) {
    return new Promise((resolve, reject) => {
        db.get('SELECT * FROM licenses WHERE license_key = ? AND status = "active"', [licenseKey], async (err, license) => {
            if (err) return reject(err);
            
            if (!license) {
                return reject(new Error('Invalid or inactive license key'));
            }

            // Check if email already exists
            db.get('SELECT * FROM users WHERE email = ?', [email], async (err, existingUser) => {
                if (err) return reject(err);
                if (existingUser) {
                    return reject(new Error('Email already registered'));
                }

                const username = email.split('@')[0] + '_' + Math.random().toString(36).substr(2, 9);
                const hashedPassword = await hashPassword(password);

                db.run(
                    'INSERT INTO users (username, email, password, streamer_lite) VALUES (?, ?, ?, 1)', // Lite by default for license
                    [username, email, hashedPassword],
                    function(err) {
                        if (err) return reject(err);
                        
                        const userId = this.lastID;
                        
                        // Update license to be used
                        db.run(
                            'UPDATE licenses SET user_id = ?, status = "used" WHERE id = ?',
                            [userId, license.id],
                            (err) => {
                                if (err) return reject(err);
                                
                                const token = generateToken(userId);
                                
                                db.run(
                                    'INSERT INTO sessions (user_id, token, expires_at) VALUES (?, ?, datetime("now", "+7 days"))',
                                    [userId, token],
                                    (err) => {
                                        if (err) return reject(err);
                                        
                                        resolve({
                                            id: userId,
                                            username,
                                            email,
                                            token,
                                            license_key: licenseKey
                                        });
                                    }
                                );
                            }
                        );
                    }
                );
            });
        });
    });
}

// Get user by token
function getUserByToken(token) {
    return new Promise((resolve, reject) => {
        const decoded = verifyToken(token);
        if (!decoded) return reject(new Error('Invalid token'));

        db.get('SELECT id, username, email, status, streamer_lite, streamer_pro, streamer_max, streamer_ultra, expires_at FROM users WHERE id = ?', [decoded.userId], (err, user) => {
            if (err) return reject(err);
            if (!user) return reject(new Error('User not found'));
            
            // Check if account expired
            if (user.expires_at && new Date() > new Date(user.expires_at)) {
                return reject(new Error('Account expired. Contact admin for extension.'));
            }

            // Check if user is blocked
            if (user.status === 'blocked') {
                return reject(new Error('Your account has been blocked. Please contact support.'));
            }

            // Tier gating
            if (!user.streamer_lite && !user.streamer_pro && !user.streamer_max && !user.streamer_ultra) {
                return reject(new Error('Streamer tier required. Join our Discord: https://discord.gg/G54H6hpfrc'));
            }
            
            resolve(user);
        });
    });
}

module.exports = {
    registerUser,
    loginUser,
    registerWithLicense,
    getUserByToken,
    generateToken,
    verifyToken
};
