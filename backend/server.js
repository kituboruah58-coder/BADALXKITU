const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const path = require('path');
const net = require('net');
const fs = require('fs');
const http = require('http');
const https = require('https');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const auth = require('./auth');
const admin = require('./admin');
const db = require('./database');

const app = express();
const PORT = process.env.PORT || 5000;
const ADMIN_PORT = process.env.ADMIN_PORT || 5001;
const ADMIN_LISTEN_PORT = Number(ADMIN_PORT) === Number(PORT) ? Number(PORT) + 1 : ADMIN_PORT;
const EXE_SIGNING_SECRET = process.env.EXE_SIGNING_SECRET || 'cloudx-exe-signing-v1';
const EXE_SIGNATURE_WINDOW_SECONDS = Math.max(60, Number(process.env.EXE_SIGNATURE_WINDOW_SECONDS || 300));
const EXE_LOGIN_TOKEN_SECRET = process.env.EXE_LOGIN_TOKEN_SECRET || 'exe-login-secret-change-this';
const EXE_LOGIN_TOKEN_EXPIRY = process.env.EXE_LOGIN_TOKEN_EXPIRY || '15m';
const EXE_MAX_FAILED_ATTEMPTS = Math.max(3, Number(process.env.EXE_MAX_FAILED_ATTEMPTS || 5));
const EXE_LOCK_MINUTES = Math.max(1, Number(process.env.EXE_LOCK_MINUTES || 15));
const EXE_SECURITY_WEBHOOK_URL = String(process.env.EXE_SECURITY_WEBHOOK_URL || process.env.DISCORD_WEBHOOK_URL || '').trim();
const EXE_AUTOBLOCK_ON_TAMPER = parseBoolean(process.env.EXE_AUTOBLOCK_ON_TAMPER, true);
const EXE_AUTOBLOCK_ON_INVALID_SIGNATURE = parseBoolean(process.env.EXE_AUTOBLOCK_ON_INVALID_SIGNATURE, true);
const EXE_AUTOBLOCK_ON_HWID_MISMATCH = parseBoolean(process.env.EXE_AUTOBLOCK_ON_HWID_MISMATCH, true);
const usedExeNonces = new Map();

// Middleware
app.use(cors({
    origin: '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    credentials: true
}));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

function normalizeIp(rawIp) {
    if (!rawIp) return '';
    const firstValue = String(rawIp).split(',')[0].trim();
    if (!firstValue) return '';
    if (firstValue.startsWith('::ffff:')) return firstValue.replace('::ffff:', '');
    if (firstValue === '::1') return '127.0.0.1';
    return firstValue;
}

function isPrivateOrLoopbackIp(ip) {
    if (!ip) return true;
    if (ip === '127.0.0.1' || ip === '::1') return true;
    if (ip.startsWith('10.')) return true;
    if (ip.startsWith('192.168.')) return true;
    if (ip.startsWith('169.254.')) return true;
    if (/^172\.(1[6-9]|2\d|3[0-1])\./.test(ip)) return true;
    const lowerIp = ip.toLowerCase();
    if (lowerIp.startsWith('fc') || lowerIp.startsWith('fd')) return true; // Unique local IPv6
    if (lowerIp.startsWith('fe8') || lowerIp.startsWith('fe9') || lowerIp.startsWith('fea') || lowerIp.startsWith('feb')) return true; // Link-local IPv6
    return false;
}

function getClientIp(req, clientReportedIp) {
    const headerCandidates = [
        req.headers['cf-connecting-ip'],
        req.headers['true-client-ip'],
        req.headers['x-real-ip'],
        req.headers['x-client-ip'],
        req.headers['fastly-client-ip'],
        req.headers['x-forwarded-for']
    ];

    for (const candidate of headerCandidates) {
        const normalized = normalizeIp(candidate);
        if (net.isIP(normalized)) {
            return normalized;
        }
    }

    const socketIp = normalizeIp(req.ip || req.connection?.remoteAddress || req.socket?.remoteAddress || '');
    const reportedIp = normalizeIp(clientReportedIp);

    if (net.isIP(socketIp)) {
        if (!isPrivateOrLoopbackIp(socketIp)) return socketIp;
        if (net.isIP(reportedIp) && !isPrivateOrLoopbackIp(reportedIp)) return reportedIp;
        return socketIp;
    }

    if (net.isIP(reportedIp)) return reportedIp;
    return 'unknown';
}

function compareVersions(versionA, versionB) {
    const a = String(versionA || '').split('.').map((part) => Number(part) || 0);
    const b = String(versionB || '').split('.').map((part) => Number(part) || 0);
    const maxLen = Math.max(a.length, b.length);
    for (let i = 0; i < maxLen; i++) {
        const av = a[i] || 0;
        const bv = b[i] || 0;
        if (av > bv) return 1;
        if (av < bv) return -1;
    }
    return 0;
}

function parseBoolean(value, fallback = false) {
    if (typeof value === 'boolean') return value;
    if (value === undefined || value === null) return fallback;
    const normalized = String(value).trim().toLowerCase();
    if (['1', 'true', 'yes', 'on'].includes(normalized)) return true;
    if (['0', 'false', 'no', 'off'].includes(normalized)) return false;
    return fallback;
}

function cleanupUsedExeNonces(nowSeconds = Math.floor(Date.now() / 1000)) {
    for (const [nonce, expiry] of usedExeNonces.entries()) {
        if (expiry < nowSeconds) {
            usedExeNonces.delete(nonce);
        }
    }
}

function createExeSignature(payload, ts, nonce) {
    const signatureBase = JSON.stringify([
        String(payload.username || ''),
        String(payload.password || ''),
        String(payload.hwid || ''),
        String(payload.clientIp || ''),
        String(ts || ''),
        String(nonce || '')
    ]);
    return crypto.createHmac('sha256', EXE_SIGNING_SECRET).update(signatureBase).digest('hex');
}

function timingSafeEqualHex(left, right) {
    const a = Buffer.from(String(left || ''), 'utf8');
    const b = Buffer.from(String(right || ''), 'utf8');
    if (a.length !== b.length) return false;
    return crypto.timingSafeEqual(a, b);
}

function verifyExeRequestSignature(req, payload) {
    const signature = String(req.headers['x-exe-signature'] || '').trim().toLowerCase();
    const tsHeader = Number(req.headers['x-exe-ts']);
    const nonce = String(req.headers['x-exe-nonce'] || '').trim();

    if (!signature || !Number.isFinite(tsHeader) || !nonce) {
        return { ok: false, error: 'Missing launcher signature headers.' };
    }

    const nowSeconds = Math.floor(Date.now() / 1000);
    if (Math.abs(nowSeconds - tsHeader) > EXE_SIGNATURE_WINDOW_SECONDS) {
        return { ok: false, error: 'Launcher request timestamp expired. Please restart launcher.' };
    }

    if (nonce.length < 8 || nonce.length > 128) {
        return { ok: false, error: 'Invalid launcher request nonce.' };
    }

    cleanupUsedExeNonces(nowSeconds);
    if (usedExeNonces.has(nonce)) {
        return { ok: false, error: 'Replay request detected. Please retry login.' };
    }

    const expected = createExeSignature(payload, tsHeader, nonce);
    if (!timingSafeEqualHex(signature, expected)) {
        return { ok: false, error: 'Launcher signature verification failed.' };
    }

    usedExeNonces.set(nonce, nowSeconds + EXE_SIGNATURE_WINDOW_SECONDS);
    return { ok: true };
}

function resolveHighestTier(tiers) {
    if (tiers.streamer_ultra) return 'ultra';
    if (tiers.streamer_max) return 'max';
    if (tiers.streamer_pro) return 'pro';
    if (tiers.streamer_lite) return 'lite';
    return 'none';
}

function dbGetAsync(sql, params = []) {
    return new Promise((resolve, reject) => {
        db.get(sql, params, (err, row) => {
            if (err) reject(err);
            else resolve(row || null);
        });
    });
}

function dbRunAsync(sql, params = []) {
    return new Promise((resolve, reject) => {
        db.run(sql, params, function(err) {
            if (err) reject(err);
            else resolve({ changes: this.changes, lastID: this.lastID });
        });
    });
}

function postJson(urlString, payload) {
    return new Promise((resolve, reject) => {
        if (!urlString) {
            resolve({ skipped: true });
            return;
        }

        let parsed;
        try {
            parsed = new URL(urlString);
        } catch (error) {
            reject(error);
            return;
        }

        const raw = JSON.stringify(payload || {});
        const isHttps = parsed.protocol === 'https:';
        const client = isHttps ? https : http;
        const req = client.request(
            {
                method: 'POST',
                hostname: parsed.hostname,
                port: parsed.port || (isHttps ? 443 : 80),
                path: `${parsed.pathname}${parsed.search || ''}`,
                headers: {
                    'Content-Type': 'application/json',
                    'Content-Length': Buffer.byteLength(raw)
                },
                timeout: 8000
            },
            (res) => {
                res.on('data', () => {});
                res.on('end', () => resolve({ statusCode: res.statusCode || 0 }));
            }
        );

        req.on('timeout', () => {
            req.destroy(new Error('Webhook request timed out'));
        });
        req.on('error', reject);
        req.write(raw);
        req.end();
    });
}

async function sendSecurityAlertToDiscord(eventData) {
    try {
        if (!EXE_SECURITY_WEBHOOK_URL) return;

        const payload = {
            username: 'CloudX Security',
            embeds: [
                {
                    title: 'CloudX EXE Security Alert',
                    color: 16726072,
                    fields: [
                        { name: 'Event', value: String(eventData.reason || 'unknown'), inline: true },
                        { name: 'Blocked', value: eventData.blocked ? 'Yes' : 'No', inline: true },
                        { name: 'Username', value: String(eventData.username || 'unknown'), inline: true },
                        { name: 'IP', value: String(eventData.ip || 'unknown'), inline: true },
                        { name: 'HWID', value: String(eventData.hwid || 'unknown').slice(0, 1024), inline: false },
                        { name: 'Details', value: String(eventData.details || 'n/a').slice(0, 1024), inline: false }
                    ],
                    footer: { text: 'CloudX Anti-Tamper' },
                    timestamp: new Date().toISOString()
                }
            ]
        };

        await postJson(EXE_SECURITY_WEBHOOK_URL, payload);
    } catch (error) {
        console.error('Security webhook error:', error.message || error);
    }
}

async function handleExeSecurityEvent({ username, ip, hwid, reason, details, shouldBlock = false }) {
    const normalizedUsername = String(username || '').trim();
    const normalizedIp = String(ip || 'unknown').trim() || 'unknown';
    const normalizedHwid = String(hwid || 'unknown').trim().slice(0, 256) || 'unknown';
    const normalizedReason = String(reason || 'unknown').slice(0, 120);
    const normalizedDetails = String(details || '').slice(0, 512);

    let exeUser = null;
    let blocked = false;
    try {
        if (normalizedUsername) {
            exeUser = await dbGetAsync('SELECT id, linked_user_id FROM exe_users WHERE username = ?', [normalizedUsername]);
        }

        if (exeUser) {
            if (shouldBlock) {
                await dbRunAsync(
                    `UPDATE exe_users
                     SET status = 'blocked',
                         last_ip = ?,
                         last_hwid = ?,
                         updated_at = CURRENT_TIMESTAMP
                     WHERE id = ?`,
                    [normalizedIp, normalizedHwid, exeUser.id]
                );
                blocked = true;
            } else {
                await dbRunAsync(
                    `UPDATE exe_users
                     SET last_ip = ?,
                         last_hwid = ?,
                         updated_at = CURRENT_TIMESTAMP
                     WHERE id = ?`,
                    [normalizedIp, normalizedHwid, exeUser.id]
                );
            }

            if (exeUser.linked_user_id) {
                await dbRunAsync(
                    'UPDATE users SET last_ip = ?, last_hwid = ?, last_login = CURRENT_TIMESTAMP WHERE id = ?',
                    [normalizedIp, normalizedHwid, exeUser.linked_user_id]
                );
            }
        }
    } catch (error) {
        console.error('Security event database update error:', error.message || error);
    }

    await sendSecurityAlertToDiscord({
        username: normalizedUsername || 'unknown',
        ip: normalizedIp,
        hwid: normalizedHwid,
        reason: normalizedReason,
        details: normalizedDetails,
        blocked
    });

    return { blocked };
}

// Admin token verification middleware
function verifyAdminToken(req, res, next) {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        
        if (!token) {
            return res.status(401).json({ error: 'No token provided' });
        }

        const decoded = admin.verifyAdminToken(token);
        if (!decoded) {
            return res.status(401).json({ error: 'Invalid or expired token' });
        }

        req.adminId = decoded.adminId;
        next();
    } catch (error) {
        res.status(401).json({ error: 'Authentication failed' });
    }
}

// Serve static files from frontend
app.use(express.static(path.join(__dirname, '../frontend')));
app.use('/admin', express.static(path.join(__dirname, '../admin')));

// Routes

// Health check
app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', message: 'Server is running' });
});

// Register - Disabled, use admin dashboard
app.post('/api/auth/register', async (req, res) => {
    try {
        res.status(403).json({ error: 'Public registration disabled. Use admin dashboard to create accounts.' });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// Login
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password, hwid, clientIp } = req.body;

        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password are required' });
        }

        const loginResult = await auth.loginUser(email, password);
        const userId = loginResult.id;
        const ip = getClientIp(req, clientIp);

        // Update last login info
        await new Promise((resolve, reject) => {
            db.run(
                'UPDATE users SET last_ip = ?, last_hwid = ?, last_login = CURRENT_TIMESTAMP WHERE id = ?',
                [ip, hwid || 'unknown', userId],
                function(err) {
                    if (err) reject(err);
                    else resolve();
                }
            );
        });

        res.json({
            message: 'Login successful',
            user: loginResult,
            token: loginResult.token
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(401).json({ error: error.message });
    }
});

// Device report (for desktop reporter app)
app.post('/api/auth/device-report', async (req, res) => {
    try {
        const { email, password, hwid, clientIp } = req.body;

        if (!email || !password || !hwid) {
            return res.status(400).json({ error: 'Email, password and hwid are required' });
        }

        const user = await new Promise((resolve, reject) => {
            db.get('SELECT id, email, password, status, expires_at FROM users WHERE email = ?', [email], (err, row) => {
                if (err) reject(err);
                else resolve(row);
            });
        });

        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        const passwordOk = await bcrypt.compare(password, user.password);
        if (!passwordOk) {
            return res.status(401).json({ error: 'Invalid password' });
        }

        if (user.status === 'blocked') {
            return res.status(403).json({ error: 'Your account has been blocked. Please contact support.' });
        }

        if (user.expires_at && new Date() > new Date(user.expires_at)) {
            return res.status(403).json({ error: 'Account expired. Contact admin for extension.' });
        }

        const ip = getClientIp(req, clientIp);
        await new Promise((resolve, reject) => {
            db.run(
                'UPDATE users SET last_ip = ?, last_hwid = ?, last_login = CURRENT_TIMESTAMP WHERE id = ?',
                [ip, String(hwid).slice(0, 256), user.id],
                function(err) {
                    if (err) reject(err);
                    else resolve();
                }
            );
        });

        res.json({ message: 'Device info updated successfully', last_ip: ip, last_hwid: String(hwid).slice(0, 256) });
    } catch (error) {
        console.error('Device report error:', error);
        res.status(500).json({ error: 'Failed to update device info' });
    }
});

// EXE login (Python launcher)
app.post('/api/exe/login', async (req, res) => {
    try {
        const { username, password, hwid, clientIp } = req.body;
        const loginUsername = String(username || '').trim();
        const ip = getClientIp(req, clientIp);
        const sanitizedHwid = String(hwid || '').slice(0, 256) || 'unknown';

        if (!loginUsername || !password) {
            return res.status(400).json({ error: 'Username and password are required' });
        }

        if (!hwid) {
            return res.status(400).json({ error: 'HWID is required' });
        }

        const signatureCheck = verifyExeRequestSignature(req, { username, password, hwid, clientIp });
        if (!signatureCheck.ok) {
            await handleExeSecurityEvent({
                username,
                ip,
                hwid: sanitizedHwid,
                reason: 'invalid_signature',
                details: signatureCheck.error,
                shouldBlock: EXE_AUTOBLOCK_ON_INVALID_SIGNATURE
            });
            return res.status(401).json({ error: signatureCheck.error });
        }

        let exeUser = await new Promise((resolve, reject) => {
            db.get(
                'SELECT * FROM exe_users WHERE LOWER(TRIM(username)) = LOWER(TRIM(?))',
                [loginUsername],
                (err, row) => {
                if (err) reject(err);
                else resolve(row);
                }
            );
        });

        if (!exeUser) {
            const mainUser = await new Promise((resolve, reject) => {
                db.get(
                    `SELECT id, username, email, password, status, expires_at 
                     FROM users 
                     WHERE LOWER(TRIM(username)) = LOWER(TRIM(?)) OR LOWER(TRIM(email)) = LOWER(TRIM(?))`,
                    [loginUsername, loginUsername],
                    (err, row) => {
                        if (err) reject(err);
                        else resolve(row || null);
                    }
                );
            });

            if (!mainUser) {
                await handleExeSecurityEvent({
                    username,
                    ip,
                    hwid: sanitizedHwid,
                    reason: 'unknown_exe_user',
                    details: 'EXE login attempted with non-existent username',
                    shouldBlock: false
                });
                return res.status(404).json({ error: 'EXE user not found. Create this account in Admin > EXE Users tab.' });
            }

            const mainPasswordOk = await bcrypt.compare(password, mainUser.password);
            if (!mainPasswordOk) {
                return res.status(401).json({ error: 'Invalid username or password.' });
            }

            if (mainUser.status === 'blocked') {
                return res.status(403).json({ error: 'Main app account is blocked. Contact developer on Discord.' });
            }

            if (mainUser.expires_at && new Date() > new Date(mainUser.expires_at)) {
                return res.status(403).json({ error: 'Main app account expired. Contact developer for renewal.' });
            }

            await new Promise((resolve, reject) => {
                db.run(
                    `INSERT OR IGNORE INTO exe_users 
                     (username, password, status, linked_user_id, last_ip, last_hwid, bound_hwid, last_login, updated_at) 
                     VALUES (?, ?, 'active', ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`,
                    [loginUsername, mainUser.password, mainUser.id, ip, sanitizedHwid, sanitizedHwid],
                    function(err) {
                        if (err) reject(err);
                        else resolve();
                    }
                );
            });

            exeUser = await new Promise((resolve, reject) => {
                db.get(
                    'SELECT * FROM exe_users WHERE LOWER(TRIM(username)) = LOWER(TRIM(?))',
                    [loginUsername],
                    (err, row) => {
                        if (err) reject(err);
                        else resolve(row || null);
                    }
                );
            });

            if (!exeUser) {
                return res.status(500).json({ error: 'Failed to provision EXE account. Please contact developer.' });
            }
        }

        if (exeUser.status === 'blocked') {
            await handleExeSecurityEvent({
                username,
                ip,
                hwid: sanitizedHwid,
                reason: 'blocked_account_attempt',
                details: 'Blocked EXE account attempted login',
                shouldBlock: false
            });
            return res.status(403).json({ error: 'Account blocked. Contact developer on Discord.' });
        }

        if (exeUser.lock_until && new Date(exeUser.lock_until) > new Date()) {
            const waitMinutes = Math.max(1, Math.ceil((new Date(exeUser.lock_until).getTime() - Date.now()) / 60000));
            await handleExeSecurityEvent({
                username,
                ip,
                hwid: sanitizedHwid,
                reason: 'locked_account_attempt',
                details: `Attempted during lockout (${waitMinutes} min left)`,
                shouldBlock: false
            });
            return res.status(429).json({ error: `Too many failed attempts. Try again in ${waitMinutes} minute(s).` });
        }

        const passwordOk = await bcrypt.compare(password, exeUser.password);
        if (!passwordOk) {
            const failedAttempts = Number(exeUser.failed_attempts || 0) + 1;
            let lockUntil = null;
            if (failedAttempts >= EXE_MAX_FAILED_ATTEMPTS) {
                lockUntil = new Date(Date.now() + EXE_LOCK_MINUTES * 60 * 1000).toISOString();
            }

            await new Promise((resolve, reject) => {
                db.run(
                    'UPDATE exe_users SET failed_attempts = ?, lock_until = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
                    [failedAttempts, lockUntil, exeUser.id],
                    function(err) {
                        if (err) reject(err);
                        else resolve();
                    }
                );
            });

            if (lockUntil) {
                await handleExeSecurityEvent({
                    username,
                    ip,
                    hwid: sanitizedHwid,
                    reason: 'password_fail_lockout',
                    details: `Failed attempts reached ${failedAttempts}`,
                    shouldBlock: false
                });
                return res.status(429).json({ error: `Too many failed attempts. Account locked for ${EXE_LOCK_MINUTES} minutes.` });
            }

            return res.status(401).json({ error: 'Invalid username or password.' });
        }

        const boundHwid = exeUser.bound_hwid ? String(exeUser.bound_hwid) : '';
        const hwidEnforced = Number(exeUser.hwid_enforced ?? 1) === 1;

        if (hwidEnforced && boundHwid && boundHwid !== sanitizedHwid) {
            await handleExeSecurityEvent({
                username,
                ip,
                hwid: sanitizedHwid,
                reason: 'hwid_mismatch',
                details: `Bound HWID ${boundHwid.slice(0, 80)} does not match login device.`,
                shouldBlock: EXE_AUTOBLOCK_ON_HWID_MISMATCH
            });
            return res.status(403).json({ error: 'Device mismatch. This account is locked to another device. Contact developer on Discord.' });
        }

        const linkedUser = await new Promise((resolve, reject) => {
            if (exeUser.linked_user_id) {
                db.get(
                    `SELECT id, username, email, status, expires_at, streamer_lite, streamer_pro, streamer_max, streamer_ultra
                     FROM users WHERE id = ?`,
                    [exeUser.linked_user_id],
                    (err, row) => {
                        if (err) reject(err);
                        else resolve(row || null);
                    }
                );
                return;
            }

            db.get(
                `SELECT id, username, email, status, expires_at, streamer_lite, streamer_pro, streamer_max, streamer_ultra
                 FROM users WHERE username = ? OR email = ?`,
                [exeUser.username, exeUser.username],
                (err, row) => {
                    if (err) reject(err);
                    else resolve(row || null);
                }
            );
        });

        if (linkedUser?.status === 'blocked') {
            return res.status(403).json({ error: 'Main app account is blocked. Contact developer on Discord.' });
        }

        if (linkedUser?.expires_at && new Date() > new Date(linkedUser.expires_at)) {
            return res.status(403).json({ error: 'Main app account expired. Contact developer for renewal.' });
        }

        await new Promise((resolve, reject) => {
            db.run(
                `UPDATE exe_users 
                 SET last_ip = ?, 
                     last_hwid = ?, 
                     bound_hwid = COALESCE(bound_hwid, ?),
                     failed_attempts = 0,
                     lock_until = NULL,
                     last_login = CURRENT_TIMESTAMP, 
                     updated_at = CURRENT_TIMESTAMP 
                 WHERE id = ?`,
                [ip, sanitizedHwid, sanitizedHwid, exeUser.id],
                function(err) {
                    if (err) reject(err);
                    else resolve();
                }
            );
        });

        // Also reflect EXE login telemetry in main users table so it appears in "All Users"
        const linkedUserId = linkedUser?.id || exeUser.linked_user_id || null;
        if (linkedUserId) {
            await new Promise((resolve, reject) => {
                db.run(
                    'UPDATE users SET last_ip = ?, last_hwid = ?, last_login = CURRENT_TIMESTAMP WHERE id = ?',
                    [ip, sanitizedHwid, linkedUserId],
                    function(err) {
                        if (err) reject(err);
                        else resolve();
                    }
                );
            });
        } else {
            await new Promise((resolve, reject) => {
                db.run(
                    'UPDATE users SET last_ip = ?, last_hwid = ?, last_login = CURRENT_TIMESTAMP WHERE username = ? OR email = ?',
                    [ip, sanitizedHwid, exeUser.username, exeUser.username],
                    function(err) {
                        if (err) reject(err);
                        else resolve();
                    }
                );
            });
        }

        const tiers = {
            streamer_lite: !!linkedUser?.streamer_lite,
            streamer_pro: !!linkedUser?.streamer_pro,
            streamer_max: !!linkedUser?.streamer_max,
            streamer_ultra: !!linkedUser?.streamer_ultra
        };
        const activeTier = resolveHighestTier(tiers);
        const token = jwt.sign(
            { exe_user_id: exeUser.id, username: exeUser.username, hwid: sanitizedHwid },
            EXE_LOGIN_TOKEN_SECRET,
            { expiresIn: EXE_LOGIN_TOKEN_EXPIRY }
        );
        const launchUrl = process.env.MAIN_APP_URL || `http://localhost:${PORT}/dashboard.html`;
        res.json({
            message: 'EXE login successful',
            launch_url: launchUrl,
            token,
            token_type: 'Bearer',
            token_expires_in: EXE_LOGIN_TOKEN_EXPIRY,
            tiers,
            active_tier: activeTier,
            profile: { id: exeUser.id, username: exeUser.username, bound_hwid: boundHwid || sanitizedHwid }
        });
    } catch (error) {
        console.error('EXE login error:', error);
        res.status(500).json({ error: 'Failed to login via EXE' });
    }
});

// EXE anti-tamper report
app.post('/api/exe/tamper', async (req, res) => {
    try {
        const { username, hwid, clientIp, reason, details, launcher_version } = req.body || {};
        const ip = getClientIp(req, clientIp);
        const sanitizedHwid = String(hwid || '').slice(0, 256) || 'unknown';

        const signatureCheck = verifyExeRequestSignature(req, {
            username: username || '',
            password: '',
            hwid: sanitizedHwid,
            clientIp: clientIp || ''
        });

        if (!signatureCheck.ok) {
            await handleExeSecurityEvent({
                username,
                ip,
                hwid: sanitizedHwid,
                reason: 'tamper_report_invalid_signature',
                details: signatureCheck.error,
                shouldBlock: false
            });
            return res.status(401).json({ error: signatureCheck.error });
        }

        const normalizedReason = String(reason || 'tamper_detected').slice(0, 120);
        const normalizedDetails = `${String(details || '').slice(0, 420)} | launcher=${String(launcher_version || 'unknown')}`;
        const result = await handleExeSecurityEvent({
            username,
            ip,
            hwid: sanitizedHwid,
            reason: normalizedReason,
            details: normalizedDetails,
            shouldBlock: EXE_AUTOBLOCK_ON_TAMPER
        });

        res.json({
            message: 'Tamper event recorded',
            blocked: !!result.blocked
        });
    } catch (error) {
        console.error('EXE tamper report error:', error);
        res.status(500).json({ error: 'Failed to process tamper report' });
    }
});

// EXE auto-update metadata
app.get('/api/exe/update', (req, res) => {
    try {
        const currentVersion = String(req.query.current_version || '').trim();
        const latestVersion = String(process.env.EXE_LAUNCHER_VERSION || '2.6.0').trim();
        const updateRequired = parseBoolean(process.env.EXE_UPDATE_REQUIRED, false);
        const notes = process.env.EXE_UPDATE_NOTES || 'UI improvements, stronger loading animation, and security hardening.';

        const forwardedProto = String(req.headers['x-forwarded-proto'] || '').split(',')[0].trim().toLowerCase();
        const proto = forwardedProto || req.protocol || 'http';
        const host = req.get('host');
        const downloadUrl = process.env.EXE_UPDATE_URL || `${proto}://${host}/api/exe/update/download`;

        const updateAvailable = !currentVersion || compareVersions(currentVersion, latestVersion) < 0;
        res.json({
            update_available: updateAvailable,
            required: updateRequired,
            current_version: currentVersion || null,
            latest_version: latestVersion,
            download_url: downloadUrl,
            notes
        });
    } catch (error) {
        console.error('EXE update metadata error:', error);
        res.status(500).json({ error: 'Failed to fetch update metadata' });
    }
});

// EXE update binary download
app.get('/api/exe/update/download', (req, res) => {
    try {
        const configuredPath = process.env.EXE_UPDATE_FILE;
        const fallbackPath = path.join(__dirname, '../CloudXLauncher_FEATUREPACK.exe');
        const filePath = configuredPath ? path.resolve(configuredPath) : fallbackPath;

        if (!fs.existsSync(filePath)) {
            return res.status(404).json({ error: 'Update file is not available on server.' });
        }

        res.download(filePath, path.basename(filePath));
    } catch (error) {
        console.error('EXE update download error:', error);
        res.status(500).json({ error: 'Failed to download update' });
    }
});

// License registration
app.post('/api/auth/license', async (req, res) => {
    try {
        const { license, email, password, confirm, hwid, clientIp } = req.body;

        if (!license || !email || !password || !confirm) {
            return res.status(400).json({ error: 'All fields are required' });
        }

        if (password !== confirm) {
            return res.status(400).json({ error: 'Passwords do not match' });
        }

        if (!/^[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(license)) {
            return res.status(400).json({ error: 'Invalid license key format' });
        }

        const user = await auth.registerWithLicense(license, email, password);
        const userId = user.id;
        const ip = getClientIp(req, clientIp);

        // Update last login info
        await new Promise((resolve, reject) => {
            db.run(
                'UPDATE users SET last_ip = ?, last_hwid = ?, last_login = CURRENT_TIMESTAMP WHERE id = ?',
                [ip, hwid || 'unknown', userId],
                function(err) {
                    if (err) reject(err);
                    else resolve();
                }
            );
        });

        res.status(201).json({
            message: 'License activated and account created',
            user,
            token: user.token
        });
    } catch (error) {
        console.error('License registration error:', error);
        res.status(400).json({ error: error.message });
    }
});

// Get current user
app.get('/api/auth/me', async (req, res) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        
        if (!token) {
            return res.status(401).json({ error: 'No token provided' });
        }

        const user = await auth.getUserByToken(token);
        res.json(user);
    } catch (error) {
        console.error('Auth check error:', error);
        res.status(401).json({ error: error.message });
    }
});

// ======================
// ADMIN ENDPOINTS
// ======================

// Admin login
app.post('/api/admin/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password are required' });
        }

        const adminUser = await admin.adminLogin(email, password);
        res.json({
            message: 'Admin login successful',
            admin: {
                id: adminUser.id,
                email: adminUser.email
            },
            token: adminUser.token
        });
    } catch (error) {
        console.error('Admin login error:', error);
        res.status(401).json({ error: error.message });
    }
});

// Get all users (admin only)
app.get('/api/admin/users', verifyAdminToken, async (req, res) => {
    try {
        const users = await admin.getAllUsers();
        res.json(users);
    } catch (error) {
        console.error('Get users error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Get active users (admin only)
app.get('/api/admin/users/active', verifyAdminToken, async (req, res) => {
    try {
        const users = await admin.getActiveUsers();
        res.json(users);
    } catch (error) {
        console.error('Get active users error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Get user tiers (admin only)
app.get('/api/admin/users/:id/tiers', verifyAdminToken, async (req, res) => {
    try {
        const tiers = await admin.getUserTiers(req.params.id);
        res.json(tiers);
    } catch (error) {
        console.error('Get user tiers error:', error);
        res.status(404).json({ error: error.message });
    }
});

// Update user tiers (admin only)
app.put('/api/admin/users/:id/tiers', verifyAdminToken, async (req, res) => {
    try {
        const tiers = req.body;
        const result = await admin.updateUserTiers(req.params.id, tiers);
        res.json(result);
    } catch (error) {
        console.error('Update user tiers error:', error);
        res.status(400).json({ error: error.message });
    }
});


// Get user statistics (admin only)
app.get('/api/admin/users/stats', verifyAdminToken, async (req, res) => {
    try {
        const stats = await admin.getUserStatistics();
        res.json(stats);
    } catch (error) {
        console.error('Get stats error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Get user by ID (admin only)
app.get('/api/admin/users/:id', verifyAdminToken, async (req, res) => {
    try {
        const user = await admin.getUserById(req.params.id);
        res.json(user);
    } catch (error) {
        console.error('Get user error:', error);
        res.status(404).json({ error: error.message });
    }
});

// Create user (admin only)
app.post('/api/admin/users/create', verifyAdminToken, async (req, res) => {
    try {
        const { username, email, password, confirm, expires_at } = req.body;

        if (!username || !email || !password || !confirm) {
            return res.status(400).json({ error: 'All fields are required' });
        }

        if (password !== confirm) {
            return res.status(400).json({ error: 'Passwords do not match' });
        }

        if (password.length < 6) {
            return res.status(400).json({ error: 'Password must be at least 6 characters' });
        }

        if (expires_at && new Date(expires_at) < new Date()) {
            return res.status(400).json({ error: 'Expiry date cannot be in the past' });
        }

        const user = await admin.createUser(username, email, password, expires_at);
        res.status(201).json({
            message: 'User created successfully',
            user
        });
    } catch (error) {
        console.error('Create user error:', error);
        res.status(400).json({ error: error.message });
    }
});

// Block user (admin only)
app.put('/api/admin/users/:id/block', verifyAdminToken, async (req, res) => {
    try {
        const result = await admin.blockUser(req.params.id);
        res.json(result);
    } catch (error) {
        console.error('Block user error:', error);
        res.status(404).json({ error: error.message });
    }
});

// Unblock user (admin only)
app.put('/api/admin/users/:id/unblock', verifyAdminToken, async (req, res) => {
    try {
        const result = await admin.unblockUser(req.params.id);
        res.json(result);
    } catch (error) {
        console.error('Unblock user error:', error);
        res.status(404).json({ error: error.message });
    }
});

// Delete user (admin only)
app.delete('/api/admin/users/:id', verifyAdminToken, async (req, res) => {
    try {
        const result = await admin.deleteUser(req.params.id);
        res.json(result);
    } catch (error) {
        console.error('Delete user error:', error);
        res.status(404).json({ error: error.message });
    }
});

// Get all EXE users (admin only)
app.get('/api/admin/exe-users', verifyAdminToken, async (req, res) => {
    try {
        const users = await admin.getAllExeUsers();
        res.json(users);
    } catch (error) {
        console.error('Get EXE users error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Create EXE user (admin only)
app.post('/api/admin/exe-users/create', verifyAdminToken, async (req, res) => {
    try {
        const { username, password, confirm, linked_user_id } = req.body;

        if (!username || !password || !confirm) {
            return res.status(400).json({ error: 'All fields are required' });
        }

        if (password !== confirm) {
            return res.status(400).json({ error: 'Passwords do not match' });
        }

        if (password.length < 6) {
            return res.status(400).json({ error: 'Password must be at least 6 characters' });
        }

        const linkedUserId = linked_user_id ? Number(linked_user_id) : null;
        const user = await admin.createExeUser(username, password, linkedUserId);
        res.status(201).json({ message: 'EXE user created successfully', user });
    } catch (error) {
        console.error('Create EXE user error:', error);
        res.status(400).json({ error: error.message });
    }
});

// Block EXE user (admin only)
app.put('/api/admin/exe-users/:id/block', verifyAdminToken, async (req, res) => {
    try {
        const result = await admin.blockExeUser(req.params.id);
        res.json(result);
    } catch (error) {
        console.error('Block EXE user error:', error);
        res.status(404).json({ error: error.message });
    }
});

// Unblock EXE user (admin only)
app.put('/api/admin/exe-users/:id/unblock', verifyAdminToken, async (req, res) => {
    try {
        const result = await admin.unblockExeUser(req.params.id);
        res.json(result);
    } catch (error) {
        console.error('Unblock EXE user error:', error);
        res.status(404).json({ error: error.message });
    }
});

// Delete EXE user (admin only)
app.delete('/api/admin/exe-users/:id', verifyAdminToken, async (req, res) => {
    try {
        const result = await admin.deleteExeUser(req.params.id);
        res.json(result);
    } catch (error) {
        console.error('Delete EXE user error:', error);
        res.status(404).json({ error: error.message });
    }
});

app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, '../admin/dashboard.html'));
});

// Serve main HTML file for all other routes
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, '../frontend/index.html'));
});

// Start main server
app.listen(PORT, () => {
    console.log(`✓ Server running on http://localhost:${PORT}`);
    console.log(`✓ Frontend available at http://localhost:${PORT}`);
});

// Admin server on different port
const adminApp = express();
adminApp.use(cors({
    origin: '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    credentials: true
}));
adminApp.use(bodyParser.json());
adminApp.use(bodyParser.urlencoded({ extended: true }));

// Serve admin dashboard
adminApp.use(express.static(path.join(__dirname, '../admin')));

// Admin  routes
adminApp.post('/api/admin/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password are required' });
        }
        const adminUser = await admin.adminLogin(email, password);
        res.json({
            message: 'Admin login successful',
            admin: {
                id: adminUser.id,
                email: adminUser.email
            },
            token: adminUser.token
        });
    } catch (error) {
        console.error('Admin login error:', error);
        res.status(401).json({ error: error.message });
    }
});

adminApp.get('/api/admin/users', verifyAdminToken, async (req, res) => {
    try {
        const users = await admin.getAllUsers();
        res.json(users);
    } catch (error) {
        console.error('Get users error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Get active users (admin only)
adminApp.get('/api/admin/users/active', verifyAdminToken, async (req, res) => {
    try {
        const users = await admin.getActiveUsers();
        res.json(users);
    } catch (error) {
        console.error('Get active users error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Get user tiers (admin only)
adminApp.get('/api/admin/users/:id/tiers', verifyAdminToken, async (req, res) => {
    try {
        const tiers = await admin.getUserTiers(req.params.id);
        res.json(tiers);
    } catch (error) {
        console.error('Get user tiers error:', error);
        res.status(404).json({ error: error.message });
    }
});

// Update user tiers (admin only)
adminApp.put('/api/admin/users/:id/tiers', verifyAdminToken, async (req, res) => {
    try {
        const tiers = req.body;
        const result = await admin.updateUserTiers(req.params.id, tiers);
        res.json(result);
    } catch (error) {
        console.error('Update user tiers error:', error);
        res.status(400).json({ error: error.message });
    }
});


adminApp.get('/api/admin/users/stats', verifyAdminToken, async (req, res) => {
    try {
        const stats = await admin.getUserStatistics();
        res.json(stats);
    } catch (error) {
        console.error('Get stats error:', error);
        res.status(500).json({ error: error.message });
    }
});

adminApp.get('/api/admin/users/:id', verifyAdminToken, async (req, res) => {
    try {
        const user = await admin.getUserById(req.params.id);
        res.json(user);
    } catch (error) {
        console.error('Get user error:', error);
        res.status(404).json({ error: error.message });
    }
});

adminApp.post('/api/admin/users/create', verifyAdminToken, async (req, res) => {
    try {
        const { username, email, password, confirm, expires_at } = req.body;
        if (!username || !email || !password || !confirm) {
            return res.status(400).json({ error: 'All fields are required' });
        }
        if (password !== confirm) {
            return res.status(400).json({ error: 'Passwords do not match' });
        }
        if (password.length < 6) {
            return res.status(400).json({ error: 'Password must be at least 6 characters' });
        }
        if (expires_at && new Date(expires_at) < new Date()) {
            return res.status(400).json({ error: 'Expiry date cannot be in the past' });
        }
        const user = await admin.createUser(username, email, password, expires_at);
        res.status(201).json({
            message: 'User created successfully',
            user
        });
    } catch (error) {
        console.error('Create user error:', error);
        res.status(400).json({ error: error.message });
    }
});

adminApp.put('/api/admin/users/:id/block', verifyAdminToken, async (req, res) => {
    try {
        const result = await admin.blockUser(req.params.id);
        res.json(result);
    } catch (error) {
        console.error('Block user error:', error);
        res.status(404).json({ error: error.message });
    }
});

adminApp.put('/api/admin/users/:id/unblock', verifyAdminToken, async (req, res) => {
    try {
        const result = await admin.unblockUser(req.params.id);
        res.json(result);
    } catch (error) {
        console.error('Unblock user error:', error);
        res.status(404).json({ error: error.message });
    }
});

adminApp.delete('/api/admin/users/:id', verifyAdminToken, async (req, res) => {
    try {
        const result = await admin.deleteUser(req.params.id);
        res.json(result);
    } catch (error) {
        console.error('Delete user error:', error);
        res.status(404).json({ error: error.message });
    }
});

// Get all EXE users (admin only)
adminApp.get('/api/admin/exe-users', verifyAdminToken, async (req, res) => {
    try {
        const users = await admin.getAllExeUsers();
        res.json(users);
    } catch (error) {
        console.error('Get EXE users error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Create EXE user (admin only)
adminApp.post('/api/admin/exe-users/create', verifyAdminToken, async (req, res) => {
    try {
        const { username, password, confirm, linked_user_id } = req.body;

        if (!username || !password || !confirm) {
            return res.status(400).json({ error: 'All fields are required' });
        }

        if (password !== confirm) {
            return res.status(400).json({ error: 'Passwords do not match' });
        }

        if (password.length < 6) {
            return res.status(400).json({ error: 'Password must be at least 6 characters' });
        }

        const linkedUserId = linked_user_id ? Number(linked_user_id) : null;
        const user = await admin.createExeUser(username, password, linkedUserId);
        res.status(201).json({ message: 'EXE user created successfully', user });
    } catch (error) {
        console.error('Create EXE user error:', error);
        res.status(400).json({ error: error.message });
    }
});

// Block EXE user (admin only)
adminApp.put('/api/admin/exe-users/:id/block', verifyAdminToken, async (req, res) => {
    try {
        const result = await admin.blockExeUser(req.params.id);
        res.json(result);
    } catch (error) {
        console.error('Block EXE user error:', error);
        res.status(404).json({ error: error.message });
    }
});

// Unblock EXE user (admin only)
adminApp.put('/api/admin/exe-users/:id/unblock', verifyAdminToken, async (req, res) => {
    try {
        const result = await admin.unblockExeUser(req.params.id);
        res.json(result);
    } catch (error) {
        console.error('Unblock EXE user error:', error);
        res.status(404).json({ error: error.message });
    }
});

// Delete EXE user (admin only)
adminApp.delete('/api/admin/exe-users/:id', verifyAdminToken, async (req, res) => {
    try {
        const result = await admin.deleteExeUser(req.params.id);
        res.json(result);
    } catch (error) {
        console.error('Delete EXE user error:', error);
        res.status(404).json({ error: error.message });
    }
});

// Create license keys (admin only)
adminApp.post('/api/admin/licenses/create', verifyAdminToken, async (req, res) => {
    try {
        const { quantity } = req.body;
        const qty = Math.min(quantity || 1, 100); // Max 100 at a time

        if (qty < 1) {
            return res.status(400).json({ error: 'Quantity must be at least 1' });
        }

        const licenses = await admin.createLicenseKey(qty);
        res.status(201).json({
            message: `${licenses.length} license key(s) created successfully`,
            licenses
        });
    } catch (error) {
        console.error('Create licenses error:', error);
        res.status(400).json({ error: error.message });
    }
});

// Get all licenses (admin only)
adminApp.get('/api/admin/licenses', verifyAdminToken, async (req, res) => {
    try {
        const licenses = await admin.getAllLicenses();
        res.json(licenses);
    } catch (error) {
        console.error('Get licenses error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Serve admin dashboard HTML
adminApp.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, '../admin/dashboard.html'));
});

// Start admin server
adminApp.listen(ADMIN_LISTEN_PORT, () => {
    console.log(`✓ Admin dashboard running on http://localhost:${ADMIN_PORT}`);
});
