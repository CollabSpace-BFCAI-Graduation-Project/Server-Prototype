require('dotenv').config();
const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const { put, del, copy } = require('@vercel/blob');
const { query, initDatabase } = require('./db');

const app = express();
const PORT = process.env.PORT || 5000;

// Directories
const IMAGES_DIR = path.join(__dirname, 'images');
const UPLOADS_DIR = path.join(__dirname, 'uploads');

// Ensure directories exist
if (!fs.existsSync(IMAGES_DIR)) fs.mkdirSync(IMAGES_DIR, { recursive: true });
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });

// Middleware
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use('/images', express.static(IMAGES_DIR));
app.use('/uploads', express.static(UPLOADS_DIR));

// ============ PASSWORD VALIDATION ============
function validatePassword(password) {
    const errors = [];

    if (!password || password.length < 8) {
        errors.push('Password must be at least 8 characters');
    }
    if (password.length > 128) {
        errors.push('Password must be less than 128 characters');
    }
    if (!/[A-Z]/.test(password)) {
        errors.push('Password must contain an uppercase letter');
    }
    if (!/[a-z]/.test(password)) {
        errors.push('Password must contain a lowercase letter');
    }
    if (!/[0-9]/.test(password)) {
        errors.push('Password must contain a number');
    }
    if (!/[@!#$%&*\-_+=?.]/.test(password)) {
        errors.push('Password must contain a special character (@!#$%&*-_+=?.)');
    }

    return errors;
}

// ============ NORMALIZATION HELPERS ============
function normalizeEmail(email) {
    if (!email) return '';
    // Trim, lowercase, and remove dots from gmail local part
    let normalized = email.trim().toLowerCase();
    // Handle Gmail dot-insensitivity (optional, common best practice)
    const [local, domain] = normalized.split('@');
    if (domain === 'gmail.com' || domain === 'googlemail.com') {
        // Remove dots and anything after + in local part
        const cleanLocal = local.replace(/\./g, '').split('+')[0];
        normalized = `${cleanLocal}@gmail.com`;
    }
    return normalized;
}

function normalizeUsername(username) {
    if (!username) return '';
    // Trim and lowercase
    return username.trim().toLowerCase();
}

// ============ AUTH ROUTES ============
app.post('/api/auth/register', async (req, res) => {
    try {
        let { name, username, email, password } = req.body;

        // Trim all inputs
        name = name?.trim() || '';
        username = username?.trim() || '';
        email = email?.trim() || '';

        if (!name || !username || !email || !password) {
            return res.status(400).json({ error: 'All fields are required' });
        }

        // Normalize for storage and lookup
        const emailNormalized = normalizeEmail(email);
        const usernameNormalized = normalizeUsername(username);

        if (!/^[a-z0-9_]{3,20}$/.test(usernameNormalized)) {
            return res.status(400).json({ error: 'Username must be 3-20 chars, lowercase, numbers, underscores only' });
        }

        // Reserved usernames (for mention system)
        const reservedUsernames = ['everyone', 'admins', 'admin', 'owner', 'channel', 'here', 'all'];
        if (reservedUsernames.includes(usernameNormalized)) {
            return res.status(400).json({ error: 'This username is reserved and cannot be used' });
        }

        // Validate password strength
        const passwordErrors = validatePassword(password);
        if (passwordErrors.length > 0) {
            return res.status(400).json({
                error: 'Password does not meet requirements',
                passwordErrors
            });
        }

        // Check existing using normalized fields
        const existingEmail = await query.get('SELECT id FROM users WHERE emailNormalized = ? OR email = ?', [emailNormalized, email.toLowerCase()]);
        if (existingEmail) return res.status(400).json({ error: 'Email already registered' });

        const existingUsername = await query.get('SELECT id FROM users WHERE usernameNormalized = ? OR username = ?', [usernameNormalized, username.toLowerCase()]);
        if (existingUsername) return res.status(400).json({ error: 'Username already taken' });

        const colors = ['#3b82f6', '#10b981', '#f59e0b', '#ec4899', '#8b5cf6', '#ef4444', '#14b8a6', '#f97316'];
        const newUser = {
            id: uuidv4(),
            name,
            username: usernameNormalized,
            email: email.toLowerCase(),
            emailNormalized,
            usernameNormalized,
            password,
            avatarColor: colors[Math.floor(Math.random() * colors.length)],
            avatarImage: null,
            bio: '',
            createdAt: new Date().toISOString()
        };

        await query.run(
            'INSERT INTO users (id, name, username, email, emailNormalized, usernameNormalized, password, avatarColor, avatarImage, bio, createdAt) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
            [newUser.id, newUser.name, newUser.username, newUser.email, newUser.emailNormalized, newUser.usernameNormalized, newUser.password, newUser.avatarColor, newUser.avatarImage, newUser.bio, newUser.createdAt]
        );

        const { password: _, emailNormalized: __, usernameNormalized: ___, ...userWithoutSensitive } = newUser;
        res.status(201).json(userWithoutSensitive);
    } catch (err) {
        console.error('Register error:', err);
        res.status(500).json({ error: 'Registration failed' });
    }
});
// ============ ACCOUNT LOCKOUT CONFIG ============
const MAX_LOGIN_ATTEMPTS = 10;
const LOCKOUT_DURATION_MS = 60 * 10; // 1 minute
const UNLOCK_INSTRUCTIONS_FILE = path.join(__dirname, 'unlock_instructions.json');

// Helper to save unlock instructions to JSON file (simulates email)
function saveUnlockInstructions(user, unlockTime) {
    let instructions = [];
    if (fs.existsSync(UNLOCK_INSTRUCTIONS_FILE)) {
        try {
            instructions = JSON.parse(fs.readFileSync(UNLOCK_INSTRUCTIONS_FILE, 'utf8'));
        } catch (e) {
            instructions = [];
        }
    }

    instructions.push({
        userId: user.id,
        email: user.email,
        username: user.username,
        name: user.name,
        lockedAt: new Date().toISOString(),
        unlockAt: unlockTime,
        message: `Your account has been temporarily locked due to too many failed login attempts. It will be automatically unlocked at ${new Date(unlockTime).toLocaleString()}. If this wasn't you, please reset your password immediately.`,
        resetLink: `/reset-password?email=${encodeURIComponent(user.email)}`
    });

    fs.writeFileSync(UNLOCK_INSTRUCTIONS_FILE, JSON.stringify(instructions, null, 2));
    console.log(`📧 Unlock instructions saved for ${user.email}`);
}

app.post('/api/auth/login', async (req, res) => {
    try {
        let { email, username, identifier, password } = req.body;

        // Support 'identifier' field that can be email or username, or separate email/username fields
        const loginId = (identifier || email || username)?.trim() || '';

        if (!loginId) {
            return res.status(400).json({ error: 'Email or username is required' });
        }

        // Determine if it's an email or username
        const isEmail = loginId.includes('@');

        let user;
        if (isEmail) {
            const emailNormalized = normalizeEmail(loginId);
            user = await query.get(
                'SELECT * FROM users WHERE emailNormalized = ? OR email = ?',
                [emailNormalized, loginId.toLowerCase()]
            );
        } else {
            const usernameNormalized = normalizeUsername(loginId);
            user = await query.get(
                'SELECT * FROM users WHERE usernameNormalized = ? OR username = ?',
                [usernameNormalized, loginId.toLowerCase()]
            );
        }

        // If user doesn't exist, return generic error (anti-enumeration)
        if (!user) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Check if account is locked
        if (user.lockedUntil) {
            const lockExpiry = new Date(user.lockedUntil).getTime();
            const now = Date.now();

            if (now < lockExpiry) {
                const remainingMs = lockExpiry - now;
                const remainingSecs = Math.ceil(remainingMs / 1000);
                return res.status(423).json({
                    error: 'Account temporarily locked',
                    message: `Too many failed attempts. Try again in ${remainingSecs} seconds.`,
                    lockedUntil: user.lockedUntil,
                    retryAfter: remainingSecs
                });
            } else {
                // Lock expired, reset counters
                await query.run(
                    'UPDATE users SET failedLoginAttempts = 0, lockedUntil = NULL WHERE id = ?',
                    [user.id]
                );
            }
        }

        // Check password
        if (user.password !== password) {
            // Increment failed attempts
            const newAttempts = (user.failedLoginAttempts || 0) + 1;

            if (newAttempts >= MAX_LOGIN_ATTEMPTS) {
                // Lock the account
                const unlockTime = new Date(Date.now() + LOCKOUT_DURATION_MS).toISOString();
                await query.run(
                    'UPDATE users SET failedLoginAttempts = ?, lockedUntil = ?, lastFailedLoginAt = ? WHERE id = ?',
                    [newAttempts, unlockTime, new Date().toISOString(), user.id]
                );

                // Save unlock instructions (simulate email)
                saveUnlockInstructions(user, unlockTime);

                return res.status(423).json({
                    error: 'Account locked',
                    message: 'Too many failed attempts. Account locked for 1 minute. Check your email for unlock instructions.',
                    lockedUntil: unlockTime
                });
            } else {
                // Just increment counter
                await query.run(
                    'UPDATE users SET failedLoginAttempts = ?, lastFailedLoginAt = ? WHERE id = ?',
                    [newAttempts, new Date().toISOString(), user.id]
                );

                const remainingAttempts = MAX_LOGIN_ATTEMPTS - newAttempts;
                const lockoutMinutes = Math.ceil(LOCKOUT_DURATION_MS / 60000);

                // Build response with warning if 3 or fewer attempts remaining
                const response = {
                    error: 'Invalid credentials',
                    remainingAttempts
                };

                if (remainingAttempts <= 3) {
                    response.warning = true;
                    response.message = `⚠️ Warning: Only ${remainingAttempts} attempt${remainingAttempts === 1 ? '' : 's'} remaining! Your account will be locked for ${lockoutMinutes} minute${lockoutMinutes === 1 ? '' : 's'} after ${remainingAttempts} more failed attempt${remainingAttempts === 1 ? '' : 's'}.`;
                    response.lockoutDuration = lockoutMinutes;
                }

                return res.status(401).json(response);
            }
        }

        // Success! Reset failed attempts
        await query.run(
            'UPDATE users SET failedLoginAttempts = 0, lockedUntil = NULL, lastFailedLoginAt = NULL WHERE id = ?',
            [user.id]
        );

        const { password: _, emailNormalized: __, usernameNormalized: ___, failedLoginAttempts: ____, lockedUntil: _____, lastFailedLoginAt: ______, ...userWithoutSensitive } = user;
        res.json(userWithoutSensitive);
    } catch (err) {
        console.error('Login error:', err);
        res.status(500).json({ error: 'Login failed' });
    }
});

// ============ GOOGLE OAUTH 2.0 ============
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const GOOGLE_REDIRECT_URI = process.env.GOOGLE_REDIRECT_URI || 'http://localhost:5000/api/auth/google/callback';
const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:5173';

// Store for OAuth state (in production, use Redis or similar)
const oauthStates = new Map();

// Initiate Google OAuth flow
app.get('/api/auth/google', (req, res) => {
    if (!GOOGLE_CLIENT_ID) {
        return res.status(500).json({ error: 'Google OAuth not configured' });
    }

    // Generate random state for CSRF protection
    const state = require('crypto').randomBytes(32).toString('hex');
    oauthStates.set(state, { createdAt: Date.now() });

    // Clean old states (older than 10 minutes)
    for (const [key, value] of oauthStates.entries()) {
        if (Date.now() - value.createdAt > 10 * 60 * 1000) {
            oauthStates.delete(key);
        }
    }

    const authUrl = new URL('https://accounts.google.com/o/oauth2/v2/auth');
    authUrl.searchParams.set('client_id', GOOGLE_CLIENT_ID);
    authUrl.searchParams.set('redirect_uri', GOOGLE_REDIRECT_URI);
    authUrl.searchParams.set('response_type', 'code');
    authUrl.searchParams.set('scope', 'openid email profile');
    authUrl.searchParams.set('state', state);
    authUrl.searchParams.set('access_type', 'offline');
    authUrl.searchParams.set('prompt', 'consent');

    res.redirect(authUrl.toString());
});

// Google OAuth callback
app.get('/api/auth/google/callback', async (req, res) => {
    try {
        const { code, state, error: oauthError } = req.query;

        if (oauthError) {
            console.error('Google OAuth error:', oauthError);
            return res.redirect(`${FRONTEND_URL}/auth?error=oauth_denied`);
        }

        // Validate state
        if (!state || !oauthStates.has(state)) {
            return res.redirect(`${FRONTEND_URL}/auth?error=invalid_state`);
        }
        oauthStates.delete(state);

        if (!code) {
            return res.redirect(`${FRONTEND_URL}/auth?error=no_code`);
        }

        // Exchange code for tokens
        const tokenResponse = await fetch('https://oauth2.googleapis.com/token', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({
                code,
                client_id: GOOGLE_CLIENT_ID,
                client_secret: GOOGLE_CLIENT_SECRET,
                redirect_uri: GOOGLE_REDIRECT_URI,
                grant_type: 'authorization_code'
            })
        });

        const tokens = await tokenResponse.json();

        if (!tokens.access_token) {
            console.error('Token exchange failed:', tokens);
            return res.redirect(`${FRONTEND_URL}/auth?error=token_failed`);
        }

        // Get user info from Google
        const userInfoResponse = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', {
            headers: { Authorization: `Bearer ${tokens.access_token}` }
        });

        const googleUser = await userInfoResponse.json();

        if (!googleUser.id || !googleUser.email) {
            return res.redirect(`${FRONTEND_URL}/auth?error=no_user_info`);
        }

        // Check if this Google account is already linked
        let oauthLink = await query.get(
            'SELECT * FROM oauth_providers WHERE provider = ? AND providerUserId = ?',
            ['google', googleUser.id]
        );

        let user;

        if (oauthLink) {
            // Existing linked account - get user
            user = await query.get('SELECT * FROM users WHERE id = ?', [oauthLink.userId]);
        } else {
            // Check if user with this email exists
            const emailNormalized = normalizeEmail(googleUser.email);
            user = await query.get(
                'SELECT * FROM users WHERE emailNormalized = ? OR email = ?',
                [emailNormalized, googleUser.email.toLowerCase()]
            );

            if (user) {
                // Link Google to existing account
                await query.run(
                    'INSERT INTO oauth_providers (id, userId, provider, providerUserId, email, createdAt) VALUES (?, ?, ?, ?, ?, ?)',
                    [uuidv4(), user.id, 'google', googleUser.id, googleUser.email, new Date().toISOString()]
                );
            } else {
                // Create new user
                const colors = ['#3b82f6', '#10b981', '#f59e0b', '#ec4899', '#8b5cf6', '#ef4444', '#14b8a6', '#f97316'];
                const username = googleUser.email.split('@')[0].toLowerCase().replace(/[^a-z0-9_]/g, '_').slice(0, 20);

                // Ensure unique username
                let finalUsername = username;
                let counter = 1;
                while (await query.get('SELECT id FROM users WHERE username = ?', [finalUsername])) {
                    finalUsername = `${username.slice(0, 17)}${counter++}`;
                }

                const newUser = {
                    id: uuidv4(),
                    name: googleUser.name || googleUser.email.split('@')[0],
                    username: finalUsername,
                    email: googleUser.email.toLowerCase(),
                    emailNormalized: emailNormalized,
                    usernameNormalized: finalUsername,
                    password: require('crypto').randomBytes(32).toString('hex'), // Random password for OAuth users
                    avatarColor: colors[Math.floor(Math.random() * colors.length)],
                    avatarImage: googleUser.picture || null,
                    bio: '',
                    createdAt: new Date().toISOString()
                };

                await query.run(
                    'INSERT INTO users (id, name, username, email, emailNormalized, usernameNormalized, password, avatarColor, avatarImage, bio, createdAt) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                    [newUser.id, newUser.name, newUser.username, newUser.email, newUser.emailNormalized, newUser.usernameNormalized, newUser.password, newUser.avatarColor, newUser.avatarImage, newUser.bio, newUser.createdAt]
                );

                // Link Google account
                await query.run(
                    'INSERT INTO oauth_providers (id, userId, provider, providerUserId, email, createdAt) VALUES (?, ?, ?, ?, ?, ?)',
                    [uuidv4(), newUser.id, 'google', googleUser.id, googleUser.email, new Date().toISOString()]
                );

                user = newUser;
            }
        }

        if (!user) {
            return res.redirect(`${FRONTEND_URL}/auth?error=user_not_found`);
        }

        // Create a simple auth token (in production, use JWT)
        const authToken = require('crypto').randomBytes(32).toString('hex');

        // Return user data via redirect with token in URL (frontend will extract and store)
        const userData = {
            id: user.id,
            name: user.name,
            username: user.username,
            email: user.email,
            avatarColor: user.avatarColor,
            avatarImage: user.avatarImage,
            bio: user.bio
        };

        // Redirect to frontend with user data encoded in URL
        const redirectUrl = `${FRONTEND_URL}/auth/callback?user=${encodeURIComponent(JSON.stringify(userData))}`;
        res.redirect(redirectUrl);

    } catch (err) {
        console.error('Google OAuth callback error:', err);
        res.redirect(`${FRONTEND_URL}/auth?error=callback_failed`);
    }
});

// ============ USER ROUTES ============
app.get('/api/users', async (req, res) => {
    try {
        const users = await query.all('SELECT id, name, username, email, avatarColor, avatarImage, bio, createdAt FROM users');
        res.json(users);
    } catch (err) {
        console.error('Get users error:', err);
        res.status(500).json({ error: 'Failed to get users' });
    }
});

// Search public profiles - MUST be before :id route
app.get('/api/users/search', async (req, res) => {
    try {
        const { q, viewerId, limit = 50 } = req.query; // Increased default limit

        let sql = `
            SELECT id, name, username, avatarColor, avatarImage, bio, profileVisibility
            FROM users
            WHERE profileVisibility != 'private'
            AND id != ?
        `;
        const params = [viewerId || ''];

        if (q && q.length > 0) {
            const searchTerm = `%${q.toLowerCase()}%`;
            sql += ` AND (LOWER(name) LIKE ? OR LOWER(username) LIKE ?)`;
            params.push(searchTerm, searchTerm);
        }

        sql += ` LIMIT ?`;
        params.push(parseInt(limit));

        const users = await query.all(sql, params);

        // For members-only profiles, check if viewer shares a space
        // Optimization: For "all users" list (empty q), we might want to skip complex privacy checks 
        // and only show 'public' ones or do a bulk check. 
        // For now, keeping the check but knowing it might be N+1 queries. 
        // Ideally, this should be a JOIN.
        const results = [];
        for (const user of users) {
            if (user.profileVisibility === 'public') {
                results.push(user);
                continue;
            }

            if (user.profileVisibility === 'members' && viewerId) {
                const sharedSpace = await query.get(`
                    SELECT sm1.spaceId FROM space_members sm1
                    INNER JOIN space_members sm2 ON sm1.spaceId = sm2.spaceId
                    WHERE sm1.userId = ? AND sm2.userId = ?
                    LIMIT 1
                `, [viewerId, user.id]);

                if (sharedSpace) results.push(user);
            }
        }

        res.json(results);
    } catch (err) {
        console.error('Search users error:', err);
        res.status(500).json({ error: 'Failed to search users' });
    }
});

app.get('/api/users/:id', async (req, res) => {
    try {
        const user = await query.get('SELECT id, name, username, email, avatarColor, avatarImage, bio, createdAt FROM users WHERE id = ?', [req.params.id]);
        if (!user) return res.status(404).json({ error: 'User not found' });
        res.json(user);
    } catch (err) {
        console.error('Get user error:', err);
        res.status(500).json({ error: 'Failed to get user' });
    }
});

app.put('/api/users/:id', async (req, res) => {
    try {
        const { name, username, email, bio } = req.body;
        const user = await query.get('SELECT * FROM users WHERE id = ?', [req.params.id]);
        if (!user) return res.status(404).json({ error: 'User not found' });

        await query.run(
            'UPDATE users SET name = ?, username = ?, email = ?, bio = ? WHERE id = ?',
            [name || user.name, username || user.username, email || user.email, bio !== undefined ? bio : user.bio, req.params.id]
        );

        const updated = await query.get('SELECT id, name, username, email, avatarColor, avatarImage, bio, createdAt FROM users WHERE id = ?', [req.params.id]);
        res.json(updated);
    } catch (err) {
        console.error('Update user error:', err);
        res.status(500).json({ error: 'Failed to update user' });
    }
});

app.delete('/api/users/:id', async (req, res) => {
    try {
        const result = await query.run('DELETE FROM users WHERE id = ?', [req.params.id]);
        if (result.changes === 0) return res.status(404).json({ error: 'User not found' });
        res.json({ success: true });
    } catch (err) {
        console.error('Delete user error:', err);
        res.status(500).json({ error: 'Failed to delete user' });
    }
});

// ============ USER PROFILE & PRIVACY ============

// Get user's public profile (respects privacy settings)
app.get('/api/users/:id/profile', async (req, res) => {
    try {
        const viewerId = req.query.viewerId; // The user viewing the profile
        const targetId = req.params.id;

        const user = await query.get(
            'SELECT id, name, username, email, avatarColor, avatarImage, bio, createdAt, showEmail, profileVisibility FROM users WHERE id = ?',
            [targetId]
        );
        if (!user) return res.status(404).json({ error: 'User not found' });

        // Check if viewing own profile
        if (viewerId === targetId) {
            const { password, emailNormalized, usernameNormalized, failedLoginAttempts, lockedUntil, lastFailedLoginAt, ...safeUser } = user;
            return res.json({ ...safeUser, isOwnProfile: true });
        }

        // Check visibility
        if (user.profileVisibility === 'private') {
            return res.json({
                id: user.id,
                name: user.name,
                username: user.username,
                avatarColor: user.avatarColor,
                avatarImage: user.avatarImage,
                isPrivate: true
            });
        }

        if (user.profileVisibility === 'members') {
            // Check if they share any spaces
            const sharedSpace = await query.get(`
                SELECT sm1.spaceId FROM space_members sm1
                INNER JOIN space_members sm2 ON sm1.spaceId = sm2.spaceId
                WHERE sm1.userId = ? AND sm2.userId = ?
                LIMIT 1
            `, [viewerId, targetId]);

            if (!sharedSpace) {
                return res.json({
                    id: user.id,
                    name: user.name,
                    username: user.username,
                    avatarColor: user.avatarColor,
                    avatarImage: user.avatarImage,
                    isPrivate: true,
                    reason: 'members_only'
                });
            }
        }

        // Return public profile
        const profile = {
            id: user.id,
            name: user.name,
            username: user.username,
            avatarColor: user.avatarColor,
            avatarImage: user.avatarImage,
            bio: user.bio,
            createdAt: user.createdAt,
            isPrivate: false
        };

        // Include email if allowed
        if (user.showEmail) {
            profile.email = user.email;
        }

        res.json(profile);
    } catch (err) {
        console.error('Get profile error:', err);
        res.status(500).json({ error: 'Failed to get profile' });
    }
});

// Update privacy settings
app.put('/api/users/:id/privacy', async (req, res) => {
    try {
        const { showEmail, profileVisibility } = req.body;

        const user = await query.get('SELECT * FROM users WHERE id = ?', [req.params.id]);
        if (!user) return res.status(404).json({ error: 'User not found' });

        // Validate profileVisibility
        const validVisibilities = ['public', 'members', 'private'];
        if (profileVisibility && !validVisibilities.includes(profileVisibility)) {
            return res.status(400).json({ error: 'Invalid profileVisibility value' });
        }

        await query.run(
            'UPDATE users SET showEmail = ?, profileVisibility = ? WHERE id = ?',
            [
                showEmail !== undefined ? (showEmail ? 1 : 0) : user.showEmail,
                profileVisibility || user.profileVisibility || 'public',
                req.params.id
            ]
        );

        const updated = await query.get(
            'SELECT id, showEmail, profileVisibility FROM users WHERE id = ?',
            [req.params.id]
        );
        res.json(updated);
    } catch (err) {
        console.error('Update privacy error:', err);
        res.status(500).json({ error: 'Failed to update privacy settings' });
    }
});

// Get spaces shared between two users
app.get('/api/users/:id/shared-spaces', async (req, res) => {
    try {
        const targetId = req.params.id;
        const viewerId = req.query.viewerId;

        if (!viewerId) {
            return res.status(400).json({ error: 'viewerId is required' });
        }

        const sharedSpaces = await query.all(`
            SELECT s.id, s.name, s.thumbnailGradient, s.thumbnailImage, s.category
            FROM spaces s
            INNER JOIN space_members sm1 ON s.id = sm1.spaceId
            INNER JOIN space_members sm2 ON s.id = sm2.spaceId
            WHERE sm1.userId = ? AND sm2.userId = ?
        `, [viewerId, targetId]);

        res.json(sharedSpaces);
    } catch (err) {
        console.error('Get shared spaces error:', err);
        res.status(500).json({ error: 'Failed to get shared spaces' });
    }
});

// Avatar upload
app.post('/api/users/:id/avatar', async (req, res) => {
    try {
        const { imageData } = req.body;
        if (!imageData) return res.status(400).json({ error: 'No image data provided' });

        const user = await query.get('SELECT * FROM users WHERE id = ?', [req.params.id]);
        if (!user) return res.status(404).json({ error: 'User not found' });

        // Delete old avatar from Vercel Blob if exists
        if (user.avatarImage && user.avatarImage.includes('blob.vercel-storage.com')) {
            try { await del(user.avatarImage); } catch (e) { /* ignore */ }
        }

        // Parse base64 image
        const matches = imageData.match(/^data:image\/(\w+);base64,(.+)$/);
        if (!matches) return res.status(400).json({ error: 'Invalid image format' });

        const ext = matches[1] === 'jpeg' ? 'jpg' : matches[1];
        const base64Data = matches[2];
        const buffer = Buffer.from(base64Data, 'base64');
        const filename = `avatars/avatar_${req.params.id}_${Date.now()}.${ext}`;

        // Upload to Vercel Blob
        const blob = await put(filename, buffer, {
            access: 'public',
            contentType: `image/${ext}`
        });

        // Store blob URL in database
        await query.run('UPDATE users SET avatarImage = ? WHERE id = ?', [blob.url, req.params.id]);

        const updated = await query.get('SELECT id, name, username, email, avatarColor, avatarImage, bio, createdAt FROM users WHERE id = ?', [req.params.id]);
        res.json(updated);
    } catch (err) {
        console.error('Avatar upload error:', err);
        res.status(500).json({ error: 'Failed to upload avatar' });
    }
});

app.delete('/api/users/:id/avatar', async (req, res) => {
    try {
        const user = await query.get('SELECT * FROM users WHERE id = ?', [req.params.id]);
        if (!user) return res.status(404).json({ error: 'User not found' });

        // Delete from Vercel Blob if exists
        if (user.avatarImage && user.avatarImage.includes('blob.vercel-storage.com')) {
            try { await del(user.avatarImage); } catch (e) { /* ignore */ }
        }

        await query.run('UPDATE users SET avatarImage = NULL WHERE id = ?', [req.params.id]);
        const updated = await query.get('SELECT id, name, username, email, avatarColor, avatarImage, bio, createdAt FROM users WHERE id = ?', [req.params.id]);
        res.json(updated);
    } catch (err) {
        console.error('Avatar delete error:', err);
        res.status(500).json({ error: 'Failed to delete avatar' });
    }
});

// ============ SPACES ROUTES ============
app.get('/api/spaces', async (req, res) => {
    try {
        let spaces;
        if (req.query.userId) {
            spaces = await query.all(`
                SELECT s.*, u.name as ownerName
                FROM spaces s
                INNER JOIN space_members sm ON s.id = sm.spaceId
                LEFT JOIN users u ON s.ownerId = u.id
                WHERE sm.userId = ?
                ORDER BY s.createdAt DESC
            `, [req.query.userId]);
        } else {
            spaces = await query.all(`
                SELECT s.*, u.name as ownerName
                FROM spaces s
                LEFT JOIN users u ON s.ownerId = u.id
                ORDER BY s.createdAt DESC
            `);
        }

        // Enrich with members and files
        const enriched = await Promise.all(spaces.map(async space => {
            const members = await query.all(`
                SELECT sm.*, u.name, u.username, u.avatarColor, u.avatarImage
                FROM space_members sm
                LEFT JOIN users u ON sm.userId = u.id
                WHERE sm.spaceId = ?
            `, [space.id]);

            const files = await query.all(`
                SELECT f.*, u.name as uploaderName
                FROM files f
                LEFT JOIN users u ON f.uploadedBy = u.id
                WHERE f.spaceId = ?
                ORDER BY f.createdAt DESC
            `, [space.id]);

            return {
                ...space,
                thumbnail: space.thumbnailGradient || space.thumbnailImage,
                ownerName: space.ownerName || 'Unknown',
                members: members.map(m => ({
                    id: m.id,
                    odId: m.userId,
                    userId: m.userId,
                    name: m.name,
                    username: m.username,
                    role: m.role,
                    avatarColor: m.avatarColor,
                    avatarImage: m.avatarImage,
                    joinedAt: m.joinedAt
                })),
                memberCount: members.length,
                files,
                fileCount: files.length,
                requestsCount: (await query.get('SELECT COUNT(*) as count FROM join_requests WHERE spaceId = ?', [space.id]))?.count || 0
            };
        }));

        res.json(enriched);
    } catch (err) {
        console.error('Get spaces error:', err);
        res.status(500).json({ error: 'Failed to get spaces' });
    }
});

app.post('/api/spaces', async (req, res) => {
    try {
        const newSpace = {
            id: uuidv4(),
            name: req.body.name,
            thumbnailGradient: req.body.thumbnail || null,
            thumbnailImage: null,
            category: req.body.category || 'GENERAL',
            description: req.body.description || '',
            ownerId: req.body.ownerId,
            createdAt: new Date().toISOString()
        };

        await query.run(
            'INSERT INTO spaces (id, name, thumbnailGradient, thumbnailImage, category, description, ownerId, createdAt) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
            [newSpace.id, newSpace.name, newSpace.thumbnailGradient, newSpace.thumbnailImage, newSpace.category, newSpace.description, newSpace.ownerId, newSpace.createdAt]
        );

        // Add owner as member
        await query.run(
            'INSERT INTO space_members (id, spaceId, userId, role, joinedAt) VALUES (?, ?, ?, ?, ?)',
            [uuidv4(), newSpace.id, newSpace.ownerId, 'Owner', newSpace.createdAt]
        );

        // Auto-create "general" channel for the new space
        await query.run(
            'INSERT INTO channels (id, spaceId, name, description, createdBy, createdAt) VALUES (?, ?, ?, ?, ?, ?)',
            [uuidv4(), newSpace.id, 'general', 'General discussion', newSpace.ownerId, newSpace.createdAt]
        );

        res.status(201).json({ ...newSpace, thumbnail: newSpace.thumbnailGradient });
    } catch (err) {
        console.error('Create space error:', err);
        res.status(500).json({ error: 'Failed to create space' });
    }
});

// Search public spaces
app.get('/api/spaces/search', async (req, res) => {
    try {
        const { q, userId, limit = 50 } = req.query;

        // Base query
        let sql = `
            SELECT s.*, u.name as ownerName,
            (SELECT COUNT(*) FROM space_members WHERE spaceId = s.id) as memberCount
            FROM spaces s
            LEFT JOIN users u ON s.ownerId = u.id
            WHERE s.visibility = 'public'
        `;

        const params = [];

        // Add search filter if query provided
        if (q && q.length > 0) {
            const searchTerm = `%${q.toLowerCase()}%`;
            sql += ` AND (LOWER(s.name) LIKE ? OR LOWER(s.description) LIKE ?)`;
            params.push(searchTerm, searchTerm);
        }

        // Sort and limit
        sql += ` ORDER BY memberCount DESC, s.createdAt DESC LIMIT ?`;
        params.push(parseInt(limit));

        // Find public spaces matching search
        const spaces = await query.all(sql, params);

        // Check membership status for each space
        const results = await Promise.all(spaces.map(async space => {
            let status = 'none'; // none, member, pending
            if (userId) {
                const member = await query.get('SELECT id FROM space_members WHERE spaceId = ? AND userId = ?', [space.id, userId]);
                if (member) {
                    status = 'member';
                } else {
                    const request = await query.get('SELECT id FROM join_requests WHERE spaceId = ? AND userId = ?', [space.id, userId]);
                    if (request) status = 'pending';
                }
            }
            return {
                ...space,
                thumbnail: space.thumbnailGradient || space.thumbnailImage,
                membershipStatus: status
            };
        }));

        res.json(results);
    } catch (err) {
        console.error('Search spaces error:', err);
        res.status(500).json({ error: 'Failed to search spaces' });
    }
});

// Join request routes
app.post('/api/spaces/:id/join', async (req, res) => {
    try {
        const { userId } = req.body;
        const spaceId = req.params.id;

        const space = await query.get('SELECT * FROM spaces WHERE id = ?', [spaceId]);
        if (!space) return res.status(404).json({ error: 'Space not found' });

        // Check if already member
        const member = await query.get('SELECT id FROM space_members WHERE spaceId = ? AND userId = ?', [spaceId, userId]);
        if (member) return res.status(400).json({ error: 'Already a member' });

        // Check if user is banned
        const banned = await query.get('SELECT id FROM space_bans WHERE spaceId = ? AND userId = ?', [spaceId, userId]);
        if (banned) return res.status(403).json({ error: 'You are banned from this space' });

        // Check if already pending
        const request = await query.get('SELECT id FROM join_requests WHERE spaceId = ? AND userId = ?', [spaceId, userId]);
        if (request) return res.status(400).json({ error: 'Request already pending' });

        // Prepare request
        const requestId = uuidv4();
        await query.run(
            'INSERT INTO join_requests (id, spaceId, userId) VALUES (?, ?, ?)',
            [requestId, spaceId, userId]
        );

        // Notify owner (implementation skipped for simplicity, would add to notifications table)

        res.json({ success: true, requestId });
    } catch (err) {
        console.error('Join space error:', err);
        res.status(500).json({ error: 'Failed to send join request' });
    }
});

app.get('/api/spaces/:id/requests', async (req, res) => {
    try {
        const requests = await query.all(`
            SELECT jr.*, u.name, u.username, u.avatarColor, u.avatarImage
            FROM join_requests jr
            JOIN users u ON jr.userId = u.id
            WHERE jr.spaceId = ?
            ORDER BY jr.createdAt DESC
        `, [req.params.id]);
        res.json(requests);
    } catch (err) {
        console.error('Get requests error:', err);
        res.status(500).json({ error: 'Failed to get requests' });
    }
});

app.post('/api/spaces/:id/requests/:requestId/approve', async (req, res) => {
    try {
        const { requestId, id: spaceId } = req.params;

        const request = await query.get('SELECT * FROM join_requests WHERE id = ?', [requestId]);
        if (!request) return res.status(404).json({ error: 'Request not found' });

        // Add member
        await query.run(
            'INSERT INTO space_members (id, spaceId, userId, role, joinedAt) VALUES (?, ?, ?, ?, ?)',
            [uuidv4(), spaceId, request.userId, 'Member', new Date().toISOString()]
        );

        // Delete request
        await query.run('DELETE FROM join_requests WHERE id = ?', [requestId]);

        res.json({ success: true });
    } catch (err) {
        console.error('Approve request error:', err);
        res.status(500).json({ error: 'Failed to approve request' });
    }
});

app.post('/api/spaces/:id/requests/:requestId/reject', async (req, res) => {
    try {
        const { requestId } = req.params;
        await query.run('DELETE FROM join_requests WHERE id = ?', [requestId]);
        res.json({ success: true });
    } catch (err) {
        console.error('Reject request error:', err);
        res.status(500).json({ error: 'Failed to reject request' });
    }
});

// Get user's own pending join requests
app.get('/api/users/:userId/join-requests', async (req, res) => {
    try {
        const requests = await query.all(`
            SELECT jr.*, s.name as spaceName, s.thumbnailGradient, s.thumbnailImage
            FROM join_requests jr
            JOIN spaces s ON jr.spaceId = s.id
            WHERE jr.userId = ?
            ORDER BY jr.createdAt DESC
        `, [req.params.userId]);
        res.json(requests);
    } catch (err) {
        console.error('Get user requests error:', err);
        res.status(500).json({ error: 'Failed to get join requests' });
    }
});

// Cancel user's own join request
app.delete('/api/users/:userId/join-requests/:requestId', async (req, res) => {
    try {
        const request = await query.get('SELECT * FROM join_requests WHERE id = ? AND userId = ?', [req.params.requestId, req.params.userId]);
        if (!request) return res.status(404).json({ error: 'Request not found' });

        await query.run('DELETE FROM join_requests WHERE id = ?', [req.params.requestId]);
        res.json({ success: true });
    } catch (err) {
        console.error('Cancel request error:', err);
        res.status(500).json({ error: 'Failed to cancel request' });
    }
});

// Upload space thumbnail image (using Vercel Blob)
app.post('/api/spaces/:id/thumbnail', async (req, res) => {
    try {
        const space = await query.get('SELECT * FROM spaces WHERE id = ?', [req.params.id]);
        if (!space) return res.status(404).json({ error: 'Space not found' });

        const { imageData } = req.body; // base64 string
        if (!imageData) return res.status(400).json({ error: 'No image data provided' });

        // Delete old thumbnail from Vercel Blob if exists
        if (space.thumbnailImage && space.thumbnailImage.includes('blob.vercel-storage.com')) {
            try { await del(space.thumbnailImage); } catch (e) { /* ignore */ }
        }

        // Parse base64
        const matches = imageData.match(/^data:image\/(\w+);base64,(.+)$/);
        if (!matches) return res.status(400).json({ error: 'Invalid image format' });

        const ext = matches[1] === 'jpeg' ? 'jpg' : matches[1];
        const base64Data = matches[2];
        const buffer = Buffer.from(base64Data, 'base64');
        const filename = `thumbnails/space_${req.params.id}_${Date.now()}.${ext}`;

        // Upload to Vercel Blob
        const blob = await put(filename, buffer, {
            access: 'public',
            contentType: `image/${ext}`
        });

        // Update database - clear gradient if image is set
        await query.run(
            'UPDATE spaces SET thumbnailImage = ?, thumbnailGradient = NULL WHERE id = ?',
            [blob.url, req.params.id]
        );

        res.json({ thumbnailImage: blob.url });
    } catch (err) {
        console.error('Upload space thumbnail error:', err);
        res.status(500).json({ error: 'Failed to upload thumbnail' });
    }
});

app.get('/api/spaces/:id', async (req, res) => {
    try {
        const space = await query.get('SELECT * FROM spaces WHERE id = ?', [req.params.id]);
        if (!space) return res.status(404).json({ error: 'Space not found' });

        const requestsCount = await query.get('SELECT COUNT(*) as count FROM join_requests WHERE spaceId = ?', [req.params.id]);

        res.json({
            ...space,
            thumbnail: space.thumbnailGradient || space.thumbnailImage,
            requestsCount: requestsCount?.count || 0
        });
    } catch (err) {
        console.error('Get space error:', err);
        res.status(500).json({ error: 'Failed to get space' });
    }
});

app.put('/api/spaces/:id', async (req, res) => {
    try {
        const space = await query.get('SELECT * FROM spaces WHERE id = ?', [req.params.id]);
        if (!space) return res.status(404).json({ error: 'Space not found' });

        const { name, description, category, thumbnail, visibility, thumbnailPosition } = req.body;
        await query.run(
            'UPDATE spaces SET name = ?, description = ?, category = ?, thumbnailGradient = ?, visibility = ?, thumbnailPosition = ? WHERE id = ?',
            [
                name || space.name,
                description !== undefined ? description : space.description,
                category || space.category,
                thumbnail || space.thumbnailGradient,
                visibility || space.visibility || 'public',
                thumbnailPosition !== undefined ? thumbnailPosition : (space.thumbnailPosition || '50% 50%'),
                req.params.id
            ]
        );

        const updated = await query.get('SELECT * FROM spaces WHERE id = ?', [req.params.id]);
        res.json({ ...updated, thumbnail: updated.thumbnailGradient || updated.thumbnailImage });
    } catch (err) {
        console.error('Update space error:', err);
        res.status(500).json({ error: 'Failed to update space' });
    }
});

app.delete('/api/spaces/:id', async (req, res) => {
    try {
        // Get space thumbnail and files first (before cascade deletes them from DB)
        const space = await query.get('SELECT thumbnailImage FROM spaces WHERE id = ?', [req.params.id]);
        const files = await query.all('SELECT downloadUrl FROM files WHERE spaceId = ?', [req.params.id]);

        const result = await query.run('DELETE FROM spaces WHERE id = ?', [req.params.id]);
        if (result.changes === 0) return res.status(404).json({ error: 'Space not found' });

        // Delete thumbnail from Vercel Blob
        if (space?.thumbnailImage && space.thumbnailImage.includes('blob.vercel-storage.com')) {
            try { await del(space.thumbnailImage); } catch (e) { /* ignore */ }
        }

        // Delete files from Vercel Blob
        for (const f of files) {
            if (f.downloadUrl && f.downloadUrl.includes('blob.vercel-storage.com')) {
                try { await del(f.downloadUrl); } catch (e) { /* ignore */ }
            }
        }

        res.json({ success: true });
    } catch (err) {
        console.error('Space delete error:', err);
        res.status(500).json({ error: 'Failed to delete space' });
    }
});

// ============ SPACE MEMBERS ROUTES ============
app.get('/api/spaces/:spaceId/members', async (req, res) => {
    try {
        const members = await query.all(`
            SELECT sm.*, u.name, u.username, u.avatarColor, u.avatarImage, u.email
            FROM space_members sm
            LEFT JOIN users u ON sm.userId = u.id
            WHERE sm.spaceId = ?
        `, [req.params.spaceId]);

        const enriched = members.map(m => ({
            id: m.id,
            odId: m.userId,
            userId: m.userId,
            name: m.name,
            username: m.username,
            email: m.email,
            role: m.role,
            avatarColor: m.avatarColor,
            avatarImage: m.avatarImage,
            joinedAt: m.joinedAt
        }));

        res.json(enriched);
    } catch (err) {
        console.error('Get members error:', err);
        res.status(500).json({ error: 'Failed to get members' });
    }
});

app.get('/api/users/:userId/spaces', async (req, res) => {
    try {
        const spaces = await query.all(`
            SELECT s.* FROM spaces s
            INNER JOIN space_members sm ON s.id = sm.spaceId
            WHERE sm.userId = ?
        `, [req.params.userId]);

        res.json(spaces.map(s => ({ ...s, thumbnail: s.thumbnailGradient || s.thumbnailImage })));
    } catch (err) {
        console.error('Get user spaces error:', err);
        res.status(500).json({ error: 'Failed to get user spaces' });
    }
});

app.post('/api/spaces/:spaceId/members', async (req, res) => {
    try {
        const { userId, role } = req.body;
        const id = uuidv4();
        const joinedAt = new Date().toISOString();

        await query.run(
            'INSERT INTO space_members (id, spaceId, userId, role, joinedAt) VALUES (?, ?, ?, ?, ?)',
            [id, req.params.spaceId, userId, role || 'Member', joinedAt]
        );
        res.status(201).json({ id, spaceId: req.params.spaceId, userId, role: role || 'Member', joinedAt });
    } catch (err) {
        res.status(400).json({ error: 'User already a member' });
    }
});

app.put('/api/spaces/:spaceId/members/:memberId', async (req, res) => {
    try {
        const { role } = req.body;
        await query.run('UPDATE space_members SET role = ? WHERE id = ?', [role, req.params.memberId]);
        res.json({ success: true });
    } catch (err) {
        console.error('Update member error:', err);
        res.status(500).json({ error: 'Failed to update member' });
    }
});

app.delete('/api/spaces/:spaceId/members/:memberId', async (req, res) => {
    try {
        const member = await query.get('SELECT * FROM space_members WHERE id = ?', [req.params.memberId]);
        if (!member) return res.status(404).json({ error: 'Member not found' });
        if (member.role === 'Owner') return res.status(403).json({ error: 'Cannot remove the owner. Transfer ownership first.' });

        await query.run('DELETE FROM space_members WHERE id = ?', [req.params.memberId]);
        res.json({ success: true });
    } catch (err) {
        console.error('Delete member error:', err);
        res.status(500).json({ error: 'Failed to delete member' });
    }
});

// Ban a member from space
app.post('/api/spaces/:spaceId/members/:memberId/ban', async (req, res) => {
    try {
        const { bannedBy, reason } = req.body;
        const member = await query.get('SELECT * FROM space_members WHERE id = ?', [req.params.memberId]);
        if (!member) return res.status(404).json({ error: 'Member not found' });
        if (member.role === 'Owner') return res.status(403).json({ error: 'Cannot ban the owner' });

        // Get space info for notification
        const space = await query.get('SELECT name FROM spaces WHERE id = ?', [req.params.spaceId]);
        const banner = await query.get('SELECT name FROM users WHERE id = ?', [bannedBy]);

        // Add to bans table
        const banId = uuidv4();
        await query.run(
            'INSERT INTO space_bans (id, spaceId, userId, bannedBy, reason, createdAt) VALUES (?, ?, ?, ?, ?, ?)',
            [banId, req.params.spaceId, member.userId, bannedBy, reason || null, new Date().toISOString()]
        );

        // Remove from members
        await query.run('DELETE FROM space_members WHERE id = ?', [req.params.memberId]);

        // Delete any pending join requests from this user
        await query.run('DELETE FROM join_requests WHERE spaceId = ? AND userId = ?', [req.params.spaceId, member.userId]);

        // Send notification to banned user
        const notifId = uuidv4();
        const banMessage = reason
            ? `You have been banned from ${space?.name || 'a space'} by ${banner?.name || 'an admin'}. Reason: ${reason}`
            : `You have been banned from ${space?.name || 'a space'} by ${banner?.name || 'an admin'}`;
        await query.run(
            'INSERT INTO notifications (id, userId, type, actorId, targetType, targetId, message, read, createdAt) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
            [notifId, member.userId, 'ban', bannedBy, 'space', req.params.spaceId, banMessage, 0, new Date().toISOString()]
        );

        res.json({ success: true });
    } catch (err) {
        console.error('Ban member error:', err);
        res.status(500).json({ error: 'Failed to ban member' });
    }
});

// Get banned users for a space
app.get('/api/spaces/:spaceId/bans', async (req, res) => {
    try {
        const bans = await query.all(`
            SELECT sb.*, u.name, u.username, u.avatarColor, u.avatarImage, 
                   banner.name as bannedByName
            FROM space_bans sb
            JOIN users u ON sb.userId = u.id
            LEFT JOIN users banner ON sb.bannedBy = banner.id
            WHERE sb.spaceId = ?
            ORDER BY sb.createdAt DESC
        `, [req.params.spaceId]);
        res.json(bans);
    } catch (err) {
        console.error('Get bans error:', err);
        res.status(500).json({ error: 'Failed to get banned users' });
    }
});

// Unban a user
app.delete('/api/spaces/:spaceId/bans/:banId', async (req, res) => {
    try {
        const ban = await query.get('SELECT * FROM space_bans WHERE id = ?', [req.params.banId]);
        if (!ban) return res.status(404).json({ error: 'Ban not found' });

        await query.run('DELETE FROM space_bans WHERE id = ?', [req.params.banId]);
        res.json({ success: true });
    } catch (err) {
        console.error('Unban error:', err);
        res.status(500).json({ error: 'Failed to unban user' });
    }
});

app.post('/api/spaces/:spaceId/leave', async (req, res) => {
    try {
        const { userId } = req.body;
        await query.run('DELETE FROM space_members WHERE spaceId = ? AND userId = ?', [req.params.spaceId, userId]);
        res.json({ success: true });
    } catch (err) {
        console.error('Leave space error:', err);
        res.status(500).json({ error: 'Failed to leave space' });
    }
}
);

// Transfer ownership
app.post('/api/spaces/:id/transfer-ownership', async (req, res) => {
    try {
        const { newOwnerId, currentOwnerId } = req.body;
        const spaceId = req.params.id;

        const space = await query.get('SELECT * FROM spaces WHERE id = ?', [spaceId]);
        if (!space) return res.status(404).json({ error: 'Space not found' });

        if (space.ownerId !== currentOwnerId) {
            return res.status(403).json({ error: 'Only the owner can transfer ownership' });
        }

        const newOwnerMember = await query.get('SELECT id FROM space_members WHERE spaceId = ? AND userId = ?', [spaceId, newOwnerId]);
        if (!newOwnerMember) return res.status(400).json({ error: 'New owner must be a member of the space' });

        // Update space owner
        await query.run('UPDATE spaces SET ownerId = ? WHERE id = ?', [newOwnerId, spaceId]);

        // Update roles
        // Old owner -> Admin
        await query.run('UPDATE space_members SET role = ? WHERE spaceId = ? AND userId = ?', ['Admin', spaceId, currentOwnerId]);
        // New owner -> Owner
        await query.run('UPDATE space_members SET role = ? WHERE spaceId = ? AND userId = ?', ['Owner', spaceId, newOwnerId]);

        res.json({ success: true });
    } catch (err) {
        console.error('Transfer ownership error:', err);
        res.status(500).json({ error: 'Failed to transfer ownership' });
    }
});

// ============ INVITE ROUTES ============
app.post('/api/spaces/:spaceId/invite', async (req, res) => {
    try {
        const { emails, inviterId, inviterName } = req.body;
        if (!emails || !Array.isArray(emails)) return res.status(400).json({ error: 'Emails required' });

        const space = await query.get('SELECT name, visibility, ownerId FROM spaces WHERE id = ?', [req.params.spaceId]);
        if (!space) return res.status(404).json({ error: 'Space not found' });

        // Check permissions for private spaces
        if (space.visibility === 'private') {
            const member = await query.get('SELECT role FROM space_members WHERE spaceId = ? AND userId = ?', [req.params.spaceId, inviterId]);
            if (!member || (member.role !== 'Owner' && member.role !== 'Admin')) {
                return res.status(403).json({ error: 'Only owners and admins can invite to private spaces' });
            }
        }

        let invited = 0;
        for (const email of emails) {
            const user = await query.get('SELECT id FROM users WHERE LOWER(email) = LOWER(?)', [email]);
            if (!user) continue;

            // Check if already member
            const isMember = await query.get('SELECT id FROM space_members WHERE spaceId = ? AND userId = ?', [req.params.spaceId, user.id]);
            if (isMember) continue;

            // Check if already invited
            const hasInvite = await query.get('SELECT id FROM space_invites WHERE spaceId = ? AND userId = ? AND status = ?', [req.params.spaceId, user.id, 'pending']);
            if (hasInvite) continue;

            const inviteId = uuidv4();
            await query.run(
                'INSERT INTO space_invites (id, spaceId, userId, inviterId, status, createdAt) VALUES (?, ?, ?, ?, ?, ?)',
                [inviteId, req.params.spaceId, user.id, inviterId, 'pending', new Date().toISOString()]
            );

            // Create notification
            await query.run(
                'INSERT INTO notifications (id, userId, type, actorId, targetType, targetId, message, read, createdAt) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
                [uuidv4(), user.id, 'invite', inviterId, 'space', req.params.spaceId, `${inviterName || 'Someone'} invited you to join ${space.name}`, 0, new Date().toISOString()]
            );

            invited++;
        }

        res.json({ success: true, invited });
    } catch (err) {
        console.error('Invite error:', err);
        res.status(500).json({ error: 'Failed to send invites' });
    }
});

// Invite by userId (for profile modal invite)
app.post('/api/spaces/:spaceId/invite-user', async (req, res) => {
    try {
        const { userId, inviterId } = req.body;
        if (!userId) return res.status(400).json({ error: 'userId required' });

        const space = await query.get('SELECT name, visibility, ownerId FROM spaces WHERE id = ?', [req.params.spaceId]);
        if (!space) return res.status(404).json({ error: 'Space not found' });

        // Check permissions for private spaces
        if (space.visibility === 'private') {
            const member = await query.get('SELECT role FROM space_members WHERE spaceId = ? AND userId = ?', [req.params.spaceId, inviterId]);
            if (!member || (member.role !== 'Owner' && member.role !== 'Admin')) {
                return res.status(403).json({ error: 'Only owners and admins can invite to private spaces' });
            }
        }

        // Check if user is banned
        const banned = await query.get('SELECT id FROM space_bans WHERE spaceId = ? AND userId = ?', [req.params.spaceId, userId]);
        if (banned) return res.status(403).json({ error: 'User is banned from this space' });

        // Check if already member
        const isMember = await query.get('SELECT id FROM space_members WHERE spaceId = ? AND userId = ?', [req.params.spaceId, userId]);
        if (isMember) return res.status(400).json({ error: 'User is already a member' });

        // Check if already invited
        const hasInvite = await query.get('SELECT id FROM space_invites WHERE spaceId = ? AND userId = ? AND status = ?', [req.params.spaceId, userId, 'pending']);
        if (hasInvite) return res.status(400).json({ error: 'User already has a pending invite' });

        // Get inviter name
        const inviter = await query.get('SELECT name FROM users WHERE id = ?', [inviterId]);

        const inviteId = uuidv4();
        await query.run(
            'INSERT INTO space_invites (id, spaceId, userId, inviterId, status, createdAt) VALUES (?, ?, ?, ?, ?, ?)',
            [inviteId, req.params.spaceId, userId, inviterId, 'pending', new Date().toISOString()]
        );

        // Create notification
        await query.run(
            'INSERT INTO notifications (id, userId, type, actorId, targetType, targetId, message, read, createdAt) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
            [uuidv4(), userId, 'invite', inviterId, 'space', req.params.spaceId, `${inviter?.name || 'Someone'} invited you to join ${space.name}`, 0, new Date().toISOString()]
        );

        res.json({ success: true });
    } catch (err) {
        console.error('Invite user error:', err);
        res.status(500).json({ error: 'Failed to send invite' });
    }
});

app.get('/api/users/:userId/invites', async (req, res) => {
    try {
        const invites = await query.all(`
            SELECT si.*, s.name as spaceName, u.name as inviterName
            FROM space_invites si
            LEFT JOIN spaces s ON si.spaceId = s.id
            LEFT JOIN users u ON si.inviterId = u.id
            WHERE si.userId = ? AND si.status = 'pending'
        `, [req.params.userId]);
        res.json(invites);
    } catch (err) {
        console.error('Get invites error:', err);
        res.status(500).json({ error: 'Failed to get invites' });
    }
});

// ============ INVITE LINKS ROUTES (Discord-Style) ============

// Get invite links for a space
app.get('/api/spaces/:id/invite-links', async (req, res) => {
    try {
        const links = await query.all(`
            SELECT il.*, u.username as creator
            FROM invite_links il
            JOIN users u ON il.creatorId = u.id
            WHERE il.spaceId = ?
            ORDER BY il.createdAt DESC
        `, [req.params.id]);

        res.json(links);
    } catch (err) {
        console.error('Get invite links error:', err);
        res.status(500).json({ error: 'Failed to fetch invite links' });
    }
});

// Create new invite link
app.post('/api/spaces/:id/invite-links', async (req, res) => {
    try {
        const { creatorId, expiresAfter, maxUses } = req.body;

        // Generate short code
        let code;
        let isUnique = false;
        while (!isUnique) {
            // Generate 6-char alphanumeric code
            code = Math.random().toString(36).substring(2, 8);
            const existing = await query.get('SELECT id FROM invite_links WHERE code = ?', [code]);
            if (!existing) isUnique = true;
        }

        // Calculate expiration
        let expiresAt = null;
        if (expiresAfter) {
            const date = new Date();
            if (expiresAfter === '30m') date.setMinutes(date.getMinutes() + 30);
            else if (expiresAfter === '1h') date.setHours(date.getHours() + 1);
            else if (expiresAfter === '6h') date.setHours(date.getHours() + 6);
            else if (expiresAfter === '12h') date.setHours(date.getHours() + 12);
            else if (expiresAfter === '1d') date.setDate(date.getDate() + 1);
            else if (expiresAfter === '7d') date.setDate(date.getDate() + 7);
            expiresAt = date.toISOString();
        }

        const id = uuidv4();
        await query.run(
            'INSERT INTO invite_links (id, code, spaceId, creatorId, expiresAt, maxUses, createdAt) VALUES (?, ?, ?, ?, ?, ?, ?)',
            [id, code, req.params.id, creatorId, expiresAt, maxUses || null, new Date().toISOString()]
        );

        const newLink = await query.get(`
            SELECT il.*, u.username as creator
            FROM invite_links il
            JOIN users u ON il.creatorId = u.id
            WHERE il.id = ?
        `, [id]);

        res.json(newLink);
    } catch (err) {
        console.error('Create invite link error:', err);
        res.status(500).json({ error: 'Failed to create invite link' });
    }
});

// Revoke invite link
app.delete('/api/invite-links/:id', async (req, res) => {
    try {
        await query.run('DELETE FROM invite_links WHERE id = ?', [req.params.id]);
        res.json({ success: true });
    } catch (err) {
        console.error('Revoke invite link error:', err);
        res.status(500).json({ error: 'Failed to revoke invite link' });
    }
});

// Get invite info (for join preview)
app.get('/api/invite/:code', async (req, res) => {
    try {
        const invite = await query.get('SELECT * FROM invite_links WHERE code = ?', [req.params.code]);
        if (!invite) return res.status(404).json({ error: 'Invite not found' });

        // Check expiration
        if (invite.expiresAt && new Date(invite.expiresAt) < new Date()) {
            return res.status(410).json({ error: 'Invite expired' });
        }

        // Check max uses
        if (invite.maxUses && invite.uses >= invite.maxUses) {
            return res.status(410).json({ error: 'Invite max uses reached' });
        }

        const space = await query.get(`
            SELECT s.id, s.name, s.description, s.thumbnailGradient, s.thumbnailImage, s.category, count(sm.id) as memberCount
            FROM spaces s
            LEFT JOIN space_members sm ON s.id = sm.spaceId
            WHERE s.id = ?
            GROUP BY s.id
        `, [invite.spaceId]);

        res.json({
            invite,
            space: {
                ...space,
                thumbnail: space.thumbnailGradient || space.thumbnailImage
            }
        });
    } catch (err) {
        console.error('Get invite info error:', err);
        res.status(500).json({ error: 'Failed to fetch invite info' });
    }
});

// Join space via invite code
app.post('/api/invite/:code/join', async (req, res) => {
    try {
        const { userId } = req.body;
        const invite = await query.get('SELECT * FROM invite_links WHERE code = ?', [req.params.code]);

        if (!invite) return res.status(404).json({ error: 'Invite not found' });
        if (invite.expiresAt && new Date(invite.expiresAt) < new Date()) return res.status(410).json({ error: 'Invite expired' });
        if (invite.maxUses && invite.uses >= invite.maxUses) return res.status(410).json({ error: 'Invite max uses reached' });

        // Check if already member
        const existing = await query.get('SELECT id FROM space_members WHERE spaceId = ? AND userId = ?', [invite.spaceId, userId]);
        if (existing) return res.status(400).json({ error: 'Already a member', spaceId: invite.spaceId });

        // Add member
        await query.run(
            'INSERT INTO space_members (id, spaceId, userId, role, joinedAt) VALUES (?, ?, ?, ?, ?)',
            [uuidv4(), invite.spaceId, userId, 'Member', new Date().toISOString()]
        );

        // Increment uses
        await query.run('UPDATE invite_links SET uses = uses + 1 WHERE id = ?', [invite.id]);

        // Create notification for join
        const user = await query.get('SELECT name FROM users WHERE id = ?', [userId]);
        const space = await query.get('SELECT name, ownerId FROM spaces WHERE id = ?', [invite.spaceId]);

        // Notify owner
        if (space.ownerId !== userId) {
            await query.run(
                'INSERT INTO notifications (id, userId, type, actorId, targetType, targetId, message, read, createdAt) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
                [uuidv4(), space.ownerId, 'join', userId, 'space', invite.spaceId, `${user.name} joined ${space.name} via invite link`, 0, new Date().toISOString()]
            );
        }

        res.json({ success: true, spaceId: invite.spaceId });
    } catch (err) {
        console.error('Join via invite error:', err);
        res.status(500).json({ error: 'Failed to join space' });
    }
});

app.post('/api/invites/:inviteId/accept', async (req, res) => {
    try {
        const invite = await query.get('SELECT * FROM space_invites WHERE id = ?', [req.params.inviteId]);
        if (!invite) return res.status(404).json({ error: 'Invite not found' });
        if (invite.status !== 'pending') return res.status(400).json({ error: 'Invite already processed' });

        // Check if user is banned from this space
        const banned = await query.get('SELECT id FROM space_bans WHERE spaceId = ? AND userId = ?', [invite.spaceId, invite.userId]);
        if (banned) return res.status(403).json({ error: 'You are banned from this space' });

        // Update invite
        await query.run('UPDATE space_invites SET status = ?, respondedAt = ? WHERE id = ?', ['accepted', new Date().toISOString(), req.params.inviteId]);

        // Add as member
        await query.run(
            'INSERT INTO space_members (id, spaceId, userId, role, joinedAt) VALUES (?, ?, ?, ?, ?)',
            [uuidv4(), invite.spaceId, invite.userId, 'Member', new Date().toISOString()]
        );

        // Notify inviter
        const space = await query.get('SELECT name FROM spaces WHERE id = ?', [invite.spaceId]);
        const user = await query.get('SELECT name FROM users WHERE id = ?', [invite.userId]);
        await query.run(
            'INSERT INTO notifications (id, userId, type, actorId, targetType, targetId, message, read, createdAt) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
            [uuidv4(), invite.inviterId, 'system', invite.userId, 'space', invite.spaceId, `${user?.name || 'Someone'} accepted your invite to join ${space?.name || 'a space'}`, 0, new Date().toISOString()]
        );

        res.json({ success: true });
    } catch (err) {
        console.error('Accept invite error:', err);
        res.status(500).json({ error: 'Failed to accept invite' });
    }
});

app.post('/api/invites/:inviteId/decline', async (req, res) => {
    try {
        await query.run('UPDATE space_invites SET status = ?, respondedAt = ? WHERE id = ?', ['declined', new Date().toISOString(), req.params.inviteId]);
        res.json({ success: true });
    } catch (err) {
        console.error('Decline invite error:', err);
        res.status(500).json({ error: 'Failed to decline invite' });
    }
});

// Get pending invites sent by a space (for revoking)
app.get('/api/spaces/:spaceId/invites', async (req, res) => {
    try {
        const invites = await query.all(`
            SELECT si.*, u.name, u.username, u.avatarColor, u.avatarImage
            FROM space_invites si
            JOIN users u ON si.userId = u.id
            WHERE si.spaceId = ? AND si.status = 'pending'
            ORDER BY si.createdAt DESC
        `, [req.params.spaceId]);
        res.json(invites);
    } catch (err) {
        console.error('Get space invites error:', err);
        res.status(500).json({ error: 'Failed to get invites' });
    }
});

// Revoke a pending invite (by inviter/admin)
app.delete('/api/invites/:inviteId', async (req, res) => {
    try {
        const invite = await query.get('SELECT * FROM space_invites WHERE id = ?', [req.params.inviteId]);
        if (!invite) return res.status(404).json({ error: 'Invite not found' });
        if (invite.status !== 'pending') return res.status(400).json({ error: 'Invite already processed' });

        await query.run('DELETE FROM space_invites WHERE id = ?', [req.params.inviteId]);

        // Also delete the invite notification
        await query.run(
            'DELETE FROM notifications WHERE type = ? AND targetId = ? AND userId = ?',
            ['invite', invite.spaceId, invite.userId]
        );

        res.json({ success: true });
    } catch (err) {
        console.error('Revoke invite error:', err);
        res.status(500).json({ error: 'Failed to revoke invite' });
    }
});

// Cancel a join request (by space admin/owner)
app.delete('/api/spaces/:spaceId/requests/:requestId', async (req, res) => {
    try {
        const request = await query.get('SELECT * FROM join_requests WHERE id = ?', [req.params.requestId]);
        if (!request) return res.status(404).json({ error: 'Request not found' });

        await query.run('DELETE FROM join_requests WHERE id = ?', [req.params.requestId]);

        // Send notification to requester
        const space = await query.get('SELECT name FROM spaces WHERE id = ?', [req.params.spaceId]);
        await query.run(
            'INSERT INTO notifications (id, userId, type, actorId, targetType, targetId, message, read, createdAt) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
            [uuidv4(), request.userId, 'system', null, 'space', req.params.spaceId, `Your request to join ${space?.name || 'a space'} was declined`, 0, new Date().toISOString()]
        );

        res.json({ success: true });
    } catch (err) {
        console.error('Cancel request error:', err);
        res.status(500).json({ error: 'Failed to cancel request' });
    }
});

// ============ NOTIFICATIONS ROUTES ============
app.get('/api/notifications', async (req, res) => {
    try {
        let notifications;
        if (req.query.userId) {
            notifications = await query.all(`
                SELECT n.*, u.name as actorName, u.avatarColor as actorAvatarColor, u.avatarImage as actorAvatarImage
                FROM notifications n
                LEFT JOIN users u ON n.actorId = u.id
                WHERE n.userId = ?
                ORDER BY n.createdAt DESC
            `, [req.query.userId]);
        } else {
            notifications = await query.all('SELECT * FROM notifications ORDER BY createdAt DESC');
        }

        // Transform for frontend compatibility
        const transformed = await Promise.all(notifications.map(async n => {
            // For invite notifications, look up the actual invite ID
            let inviteId = null;
            if (n.type === 'invite' && n.targetType === 'space') {
                const invite = await query.get('SELECT id FROM space_invites WHERE spaceId = ? AND userId = ? AND status = ?', [n.targetId, n.userId, 'pending']);
                inviteId = invite?.id || null;
            }

            return {
                id: n.id,
                userId: n.userId,
                type: n.type,
                author: n.actorName || 'System',
                text: n.message,
                target: '',
                spaceId: n.targetType === 'space' ? n.targetId : null,
                inviteId: inviteId,
                action: n.type === 'invite' ? 'View Invite' : null,
                read: !!n.read,
                createdAt: n.createdAt
            };
        }));

        res.json(transformed);
    } catch (err) {
        console.error('Get notifications error:', err);
        res.status(500).json({ error: 'Failed to get notifications' });
    }
});

app.post('/api/notifications', async (req, res) => {
    try {
        const { userId, type, actorId, targetType, targetId, message } = req.body;
        const id = uuidv4();
        await query.run(
            'INSERT INTO notifications (id, userId, type, actorId, targetType, targetId, message, read, createdAt) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
            [id, userId, type, actorId, targetType, targetId, message, 0, new Date().toISOString()]
        );
        res.status(201).json({ id });
    } catch (err) {
        console.error('Create notification error:', err);
        res.status(500).json({ error: 'Failed to create notification' });
    }
});

app.put('/api/notifications/:id/read', async (req, res) => {
    try {
        await query.run('UPDATE notifications SET read = 1 WHERE id = ?', [req.params.id]);
        res.json({ success: true });
    } catch (err) {
        console.error('Mark read error:', err);
        res.status(500).json({ error: 'Failed to mark as read' });
    }
});

app.put('/api/notifications/read-all', async (req, res) => {
    try {
        await query.run('UPDATE notifications SET read = 1');
        res.json({ success: true });
    } catch (err) {
        console.error('Mark all read error:', err);
        res.status(500).json({ error: 'Failed to mark all as read' });
    }
});

// ============ CHANNELS ROUTES ============
// Get channels for a space
app.get('/api/channels/:spaceId', async (req, res) => {
    try {
        const channels = await query.all(`
            SELECT c.*, u.name as creatorName
            FROM channels c
            LEFT JOIN users u ON c.createdBy = u.id
            WHERE c.spaceId = ?
            ORDER BY c.createdAt ASC
        `, [req.params.spaceId]);
        res.json(channels);
    } catch (err) {
        console.error('Get channels error:', err);
        res.status(500).json({ error: 'Failed to get channels' });
    }
});

// Create a channel (admin/owner only - validated on frontend)
app.post('/api/channels/:spaceId', async (req, res) => {
    try {
        const { name, description, createdBy } = req.body;
        const id = uuidv4();
        const createdAt = new Date().toISOString();

        await query.run(
            'INSERT INTO channels (id, spaceId, name, description, createdBy, createdAt) VALUES (?, ?, ?, ?, ?, ?)',
            [id, req.params.spaceId, name, description || null, createdBy, createdAt]
        );

        res.status(201).json({ id, spaceId: req.params.spaceId, name, description, createdBy, createdAt });
    } catch (err) {
        console.error('Create channel error:', err);
        res.status(500).json({ error: 'Failed to create channel' });
    }
});

// Update a channel
app.put('/api/channels/:channelId', async (req, res) => {
    try {
        const { name, description } = req.body;
        await query.run(
            'UPDATE channels SET name = ?, description = ? WHERE id = ?',
            [name, description || null, req.params.channelId]
        );
        const updated = await query.get('SELECT * FROM channels WHERE id = ?', [req.params.channelId]);
        res.json(updated);
    } catch (err) {
        console.error('Update channel error:', err);
        res.status(500).json({ error: 'Failed to update channel' });
    }
});

// Delete a channel
app.delete('/api/channels/:channelId', async (req, res) => {
    try {
        await query.run('DELETE FROM channels WHERE id = ?', [req.params.channelId]);
        res.json({ success: true });
    } catch (err) {
        console.error('Delete channel error:', err);
        res.status(500).json({ error: 'Failed to delete channel' });
    }
});

// ============ MESSAGES ROUTES ============
// Get messages for a channel
app.get('/api/messages/:channelId', async (req, res) => {
    try {
        const messages = await query.all(`
            SELECT m.*, u.name as senderName, u.avatarColor, u.avatarImage,
                   r.text as replyText, r.senderId as replySenderId,
                   r.deletedAt as replyDeletedAt,
                   ru.name as replySenderName
            FROM messages m
            LEFT JOIN users u ON m.senderId = u.id
            LEFT JOIN messages r ON m.replyToId = r.id
            LEFT JOIN users ru ON r.senderId = ru.id
            WHERE m.channelId = ?
            ORDER BY m.createdAt ASC
        `, [req.params.channelId]);

        const transformed = await Promise.all(messages.map(async (m) => {
            // Fetch attachments for this message
            let attachments = [];
            try {
                const attachmentRows = await query.all(`
                    SELECT f.id, f.name, f.type, f.mimeType, f.size, f.downloadUrl
                    FROM message_attachments ma
                    JOIN files f ON ma.fileId = f.id
                    WHERE ma.messageId = ?
                `, [m.id]);
                attachments = attachmentRows || [];
            } catch (err) {
                // Table might not exist yet
            }

            return {
                id: m.id,
                spaceId: m.spaceId,
                channelId: m.channelId,
                senderId: m.senderId,
                sender: m.type === 'system' ? 'System' : (m.senderName || 'Unknown User'),
                text: m.text,
                type: m.type,
                mentions: m.mentions ? JSON.parse(m.mentions) : [],
                time: new Date(m.createdAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
                createdAt: m.createdAt,
                avatarColor: m.avatarColor || '#9ca3af',
                avatarImage: m.avatarImage,
                // Reply info
                replyToId: m.replyToId || null,
                replyTo: m.replyToId ? {
                    text: m.replyDeletedAt ? null : m.replyText,
                    sender: m.replySenderName || 'Unknown',
                    deletedAt: m.replyDeletedAt || null
                } : null,
                // Forward info
                forwardedFromChannel: m.forwardedFromChannel || null,
                // Soft delete fields
                deletedAt: m.deletedAt || null,
                deletedBy: m.deletedBy || null,
                deletedByRole: m.deletedByRole || null,
                // Attachments
                attachments
            };
        }));

        res.json(transformed);
    } catch (err) {
        console.error('Get messages error:', err);
        res.status(500).json({ error: 'Failed to get messages' });
    }
});

app.post('/api/messages/:channelId', async (req, res) => {
    try {
        const { senderId, text, type, mentions, spaceId, replyToId, mentionEveryone, mentionRoles, attachments } = req.body;
        const id = uuidv4();
        const createdAt = new Date().toISOString();

        // Fetch sender and channel details for notifications and response
        const sender = await query.get('SELECT name, avatarColor, avatarImage FROM users WHERE id = ?', [senderId]);
        const channel = await query.get('SELECT name FROM channels WHERE id = ?', [req.params.channelId]);
        const senderName = sender?.name || 'Someone';
        const channelName = channel?.name || 'chat';

        await query.run(
            'INSERT INTO messages (id, spaceId, channelId, senderId, text, type, mentions, replyToId, createdAt) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
            [id, spaceId, req.params.channelId, senderId, text, type || 'user', mentions ? JSON.stringify(mentions) : null, replyToId || null, createdAt]
        );

        const notifiedUsers = new Set();

        // Populate message_mentions table and create detailed notifications
        if (mentions && Array.isArray(mentions) && mentions.length > 0) {
            for (const userId of mentions) {
                try {
                    // Insert mention record
                    const mentionId = uuidv4();
                    await query.run(
                        'INSERT INTO message_mentions (id, messageId, userId, createdAt) VALUES (?, ?, ?, ?)',
                        [mentionId, id, userId, createdAt]
                    );

                    // Create notification (skip self-mention)
                    if (userId !== senderId && !notifiedUsers.has(userId)) {
                        const notifId = uuidv4();
                        const notifMessage = `${senderName} mentioned you in #${channelName}`;
                        await query.run(
                            'INSERT INTO notifications (id, userId, type, actorId, targetType, targetId, message, createdAt) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                            [notifId, userId, 'mention', senderId, 'message', id, notifMessage, createdAt]
                        );
                        notifiedUsers.add(userId);
                    }
                } catch (err) {
                    console.error('Failed to process mention:', err);
                }
            }
        }

        // Handle @everyone
        if (mentionEveryone) {
            try {
                const members = await query.all('SELECT userId FROM space_members WHERE spaceId = ?', [spaceId]);
                for (const m of members) {
                    if (m.userId !== senderId && !notifiedUsers.has(m.userId)) {
                        const notifId = uuidv4();
                        const notifMessage = `${senderName} mentioned everyone in #${channelName}`;
                        await query.run(
                            'INSERT INTO notifications (id, userId, type, actorId, targetType, targetId, message, createdAt) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                            [notifId, m.userId, 'mention', senderId, 'message', id, notifMessage, createdAt]
                        );
                        notifiedUsers.add(m.userId);
                    }
                }
            } catch (err) {
                console.error('Failed to process @everyone:', err);
            }
        }

        // Handle role mentions (e.g. @admins)
        if (mentionRoles && Array.isArray(mentionRoles) && mentionRoles.length > 0) {
            try {
                const placeholders = mentionRoles.map(() => '?').join(',');
                const roleMembers = await query.all(
                    `SELECT userId FROM space_members WHERE spaceId = ? AND role IN (${placeholders})`,
                    [spaceId, ...mentionRoles]
                );

                for (const m of roleMembers) {
                    if (m.userId !== senderId && !notifiedUsers.has(m.userId)) {
                        const notifId = uuidv4();
                        // Assuming first role is representative or just generic "admins"
                        const rolesStr = mentionRoles.join('/').toLowerCase();
                        const notifMessage = `${senderName} mentioned ${rolesStr} in #${channelName}`;
                        await query.run(
                            'INSERT INTO notifications (id, userId, type, actorId, targetType, targetId, message, createdAt) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                            [notifId, m.userId, 'mention', senderId, 'message', id, notifMessage, createdAt]
                        );
                        notifiedUsers.add(m.userId);
                    }
                }
            } catch (err) {
                console.error('Failed to process role mentions:', err);
            }
        }

        // Handle attachments
        let attachmentDetails = [];
        if (attachments && Array.isArray(attachments) && attachments.length > 0) {
            for (const fileId of attachments) {
                try {
                    const attachId = uuidv4();
                    await query.run(
                        'INSERT INTO message_attachments (id, messageId, fileId, createdAt) VALUES (?, ?, ?, ?)',
                        [attachId, id, fileId, createdAt]
                    );
                    // Fetch file details
                    const fileInfo = await query.get('SELECT id, name, type, mimeType, size, downloadUrl FROM files WHERE id = ?', [fileId]);
                    if (fileInfo) {
                        attachmentDetails.push(fileInfo);
                    }
                } catch (err) {
                    console.error('Failed to process attachment:', err);
                }
            }
        }

        // Fetch reply info if replying
        let replyTo = null;
        if (replyToId) {
            const replyMsg = await query.get(`
                SELECT m.text, u.name as senderName FROM messages m
                LEFT JOIN users u ON m.senderId = u.id WHERE m.id = ?
            `, [replyToId]);
            if (replyMsg) replyTo = { text: replyMsg.text, sender: replyMsg.senderName };
        }
        res.status(201).json({
            id,
            spaceId,
            channelId: req.params.channelId,
            senderId,
            sender: sender?.name || 'User',
            text,
            type: type || 'user',
            mentions: mentions || [],
            time: new Date(createdAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
            createdAt,
            avatarColor: sender?.avatarColor || '#ec4899',
            avatarImage: sender?.avatarImage,
            replyToId: replyToId || null,
            replyTo,
            attachments: attachmentDetails
        });
    } catch (err) {
        console.error('Send message error:', err);
        res.status(500).json({ error: 'Failed to send message' });
    }
});

// Forward a message to another channel
app.post('/api/messages/:messageId/forward', async (req, res) => {
    try {
        const { targetChannelId, senderId, spaceId } = req.body;

        // Get original message
        const original = await query.get(`
            SELECT m.*, c.name as channelName FROM messages m
            LEFT JOIN channels c ON m.channelId = c.id
            WHERE m.id = ?
        `, [req.params.messageId]);

        if (!original) return res.status(404).json({ error: 'Message not found' });

        const id = uuidv4();
        const createdAt = new Date().toISOString();

        try {
            await query.run(
                'INSERT INTO messages (id, spaceId, channelId, senderId, text, type, forwardedFromChannel, createdAt) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                [id, spaceId, targetChannelId, senderId, original.text, 'user', original.channelName || 'another channel', createdAt]
            );
        } catch (dbErr) {
            console.warn('Column forwardedFromChannel might be missing, retrying without it:', dbErr.message);
            // Fallback: Insert without forwardedFromChannel column
            await query.run(
                'INSERT INTO messages (id, spaceId, channelId, senderId, text, type, createdAt) VALUES (?, ?, ?, ?, ?, ?, ?)',
                [id, spaceId, targetChannelId, senderId, original.text, 'user', createdAt]
            );
        }

        const sender = await query.get('SELECT name, avatarColor, avatarImage FROM users WHERE id = ?', [senderId]);
        res.status(201).json({
            id,
            spaceId,
            channelId: targetChannelId,
            senderId,
            sender: sender?.name || 'User',
            text: original.text,
            type: 'user',
            time: new Date(createdAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
            createdAt,
            avatarColor: sender?.avatarColor || '#ec4899',
            avatarImage: sender?.avatarImage,
            forwardedFromChannel: original.channelName || 'another channel'
        });
    } catch (err) {
        console.error('Forward message error:', err);
        res.status(500).json({ error: 'Failed to forward message' });
    }
});

app.put('/api/messages/:id', async (req, res) => {
    try {
        const { text, senderId } = req.body;
        const message = await query.get('SELECT * FROM messages WHERE id = ?', [req.params.id]);

        if (!message) return res.status(404).json({ error: 'Message not found' });

        // Check ownership
        if (message.senderId !== senderId) {
            return res.status(403).json({ error: 'You can only edit your own messages' });
        }

        // Check time limit (15 minutes)
        const age = Date.now() - new Date(message.createdAt).getTime();
        if (age > 15 * 60 * 1000) {
            return res.status(403).json({ error: 'Message cannot be edited after 15 minutes' });
        }

        await query.run('UPDATE messages SET text = ? WHERE id = ?', [text, req.params.id]);

        // Return updated message
        const updated = await query.get('SELECT m.*, u.name as senderName, u.avatarColor, u.avatarImage FROM messages m left join users u on m.senderId = u.id WHERE m.id = ?', [req.params.id]);

        res.json({
            id: updated.id,
            spaceId: updated.spaceId,
            senderId: updated.senderId,
            sender: updated.type === 'system' ? 'System' : (updated.senderName || 'Unknown User'),
            text: updated.text,
            type: updated.type,
            mentions: updated.mentions ? JSON.parse(updated.mentions) : [],
            time: new Date(updated.createdAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
            createdAt: updated.createdAt,
            avatarColor: updated.avatarColor || '#9ca3af',
            avatarImage: updated.avatarImage
        });
    } catch (err) {
        console.error('Update message error:', err);
        res.status(500).json({ error: 'Failed to update message' });
    }
});

app.delete('/api/messages/:id', async (req, res) => {
    try {
        const { senderId } = req.body; // Requester ID
        const message = await query.get('SELECT * FROM messages WHERE id = ?', [req.params.id]);

        if (!message) return res.status(404).json({ error: 'Message not found' });
        if (message.deletedAt) return res.status(400).json({ error: 'Message already deleted' });

        // Check permissions
        const space = await query.get('SELECT ownerId FROM spaces WHERE id = ?', [message.spaceId]);
        const membership = await query.get('SELECT role FROM space_members WHERE spaceId = ? AND userId = ?', [message.spaceId, senderId]);

        const isAuthor = message.senderId === senderId;
        const isAdmin = membership?.role === 'Admin' || membership?.role === 'Owner';
        const isOwner = space?.ownerId === senderId;

        const deletedAt = new Date().toISOString();
        let deletedByRole = null;

        // Condition 1: Author can delete OWN message within 15 minutes (or anytime if admin/owner)
        if (isAuthor) {
            const age = Date.now() - new Date(message.createdAt).getTime();
            // Authors who are NOT admin/owner must be within 15 min
            if (age > 15 * 60 * 1000 && !isAdmin && !isOwner) {
                return res.status(403).json({ error: 'Message cannot be deleted after 15 minutes' });
            }
            deletedByRole = 'author';
            await query.run(
                'UPDATE messages SET deletedAt = ?, deletedBy = ?, deletedByRole = ? WHERE id = ?',
                [deletedAt, senderId, deletedByRole, req.params.id]
            );
            return res.json({ success: true, deletedByRole });
        }

        // Condition 2: Admin/Owner can delete OTHER people's messages (no time limit)
        if (isAdmin || isOwner) {
            deletedByRole = isOwner ? 'Owner' : 'Admin';
            await query.run(
                'UPDATE messages SET deletedAt = ?, deletedBy = ?, deletedByRole = ? WHERE id = ?',
                [deletedAt, senderId, deletedByRole, req.params.id]
            );
            return res.json({ success: true, deletedByRole });
        }

        return res.status(403).json({ error: 'Permission denied' });
    } catch (err) {
        console.error('Delete message error:', err);
        res.status(500).json({ error: 'Failed to delete message' });
    }
});

// ============ FOLDERS ROUTES ============
// Get all folders in a space (optionally filtered by parentId)
app.get('/api/spaces/:spaceId/folders', async (req, res) => {
    try {
        const { parentId } = req.query;
        let folders;

        if (parentId === 'null' || parentId === '') {
            // Get root folders (no parent)
            folders = await query.all(`
                SELECT f.*, u.name as creatorName
                FROM folders f
                LEFT JOIN users u ON f.createdBy = u.id
                WHERE f.spaceId = ? AND f.parentId IS NULL
                ORDER BY f.name ASC
            `, [req.params.spaceId]);
        } else if (parentId) {
            // Get folders within a specific parent
            folders = await query.all(`
                SELECT f.*, u.name as creatorName
                FROM folders f
                LEFT JOIN users u ON f.createdBy = u.id
                WHERE f.spaceId = ? AND f.parentId = ?
                ORDER BY f.name ASC
            `, [req.params.spaceId, parentId]);
        } else {
            // Get all folders
            folders = await query.all(`
                SELECT f.*, u.name as creatorName
                FROM folders f
                LEFT JOIN users u ON f.createdBy = u.id
                WHERE f.spaceId = ?
                ORDER BY f.name ASC
            `, [req.params.spaceId]);
        }

        res.json(folders);
    } catch (err) {
        console.error('Get folders error:', err);
        res.status(500).json({ error: 'Failed to get folders' });
    }
});

// Get a single folder with its path (for breadcrumbs)
app.get('/api/folders/:folderId', async (req, res) => {
    try {
        const folder = await query.get(`
            SELECT f.*, u.name as creatorName
            FROM folders f
            LEFT JOIN users u ON f.createdBy = u.id
            WHERE f.id = ?
        `, [req.params.folderId]);

        if (!folder) return res.status(404).json({ error: 'Folder not found' });

        // Build path by traversing up
        const path = [folder];
        let current = folder;
        while (current.parentId) {
            const parent = await query.get('SELECT * FROM folders WHERE id = ?', [current.parentId]);
            if (parent) {
                path.unshift(parent);
                current = parent;
            } else {
                break;
            }
        }

        res.json({ folder, path });
    } catch (err) {
        console.error('Get folder error:', err);
        res.status(500).json({ error: 'Failed to get folder' });
    }
});

// Create a folder
app.post('/api/spaces/:spaceId/folders', async (req, res) => {
    try {
        const { name, parentId, createdBy } = req.body;
        if (!name) return res.status(400).json({ error: 'Folder name required' });

        const id = uuidv4();
        const createdAt = new Date().toISOString();

        await query.run(
            'INSERT INTO folders (id, spaceId, name, parentId, createdBy, createdAt) VALUES (?, ?, ?, ?, ?, ?)',
            [id, req.params.spaceId, name, parentId || null, createdBy, createdAt]
        );

        res.status(201).json({ id, spaceId: req.params.spaceId, name, parentId: parentId || null, createdBy, createdAt });
    } catch (err) {
        console.error('Create folder error:', err);
        res.status(500).json({ error: 'Failed to create folder' });
    }
});

// Rename a folder
app.put('/api/folders/:folderId', async (req, res) => {
    try {
        const { name } = req.body;
        if (!name) return res.status(400).json({ error: 'Folder name required' });

        await query.run('UPDATE folders SET name = ? WHERE id = ?', [name, req.params.folderId]);
        res.json({ success: true });
    } catch (err) {
        console.error('Update folder error:', err);
        res.status(500).json({ error: 'Failed to update folder' });
    }
});

// Delete a folder (cascades to subfolders, files get folderId set to NULL)
app.delete('/api/folders/:folderId', async (req, res) => {
    try {
        const folder = await query.get('SELECT * FROM folders WHERE id = ?', [req.params.folderId]);
        if (!folder) return res.status(404).json({ error: 'Folder not found' });

        // Delete folder (CASCADE handles subfolders, files get NULL folderId)
        await query.run('DELETE FROM folders WHERE id = ?', [req.params.folderId]);
        res.json({ success: true });
    } catch (err) {
        console.error('Delete folder error:', err);
        res.status(500).json({ error: 'Failed to delete folder' });
    }
});

// ============ FILES ROUTES ============
// Modified to support folder filtering
app.get('/api/files/:spaceId', async (req, res) => {
    try {
        const { folderId } = req.query;
        let files;

        if (folderId === 'null' || folderId === '') {
            // Get root-level files (no folder)
            files = await query.all(`
                SELECT f.*, u.name as uploaderName
                FROM files f
                LEFT JOIN users u ON f.uploadedBy = u.id
                WHERE f.spaceId = ? AND f.folderId IS NULL
            `, [req.params.spaceId]);
        } else if (folderId) {
            // Get files in a specific folder
            files = await query.all(`
                SELECT f.*, u.name as uploaderName
                FROM files f
                LEFT JOIN users u ON f.uploadedBy = u.id
                WHERE f.spaceId = ? AND f.folderId = ?
            `, [req.params.spaceId, folderId]);
        } else {
            // Get all files (for backward compatibility)
            files = await query.all(`
                SELECT f.*, u.name as uploaderName
                FROM files f
                LEFT JOIN users u ON f.uploadedBy = u.id
                WHERE f.spaceId = ?
            `, [req.params.spaceId]);
        }

        const enriched = files.map(f => ({
            ...f,
            uploaderName: f.uploaderName || 'Unknown User'
        }));

        res.json(enriched);
    } catch (err) {
        console.error('Get files error:', err);
        res.status(500).json({ error: 'Failed to get files' });
    }
});

// Copy file(s) to a different folder (Deep Copy - new blob)
// MUST be before /api/files/:spaceId to avoid :spaceId matching "copy"
app.post('/api/files/copy', async (req, res) => {
    try {
        const { fileIds, folderId, userId } = req.body;
        if (!fileIds || !Array.isArray(fileIds) || fileIds.length === 0) {
            return res.status(400).json({ error: 'File IDs array required' });
        }

        const copiedFiles = [];
        for (const fileId of fileIds) {
            const original = await query.get('SELECT * FROM files WHERE id = ?', [fileId]);
            if (!original) continue;

            const newId = uuidv4();
            const createdAt = new Date().toISOString();

            // Create a Deep Copy of the blob if it has a URL
            // If downloadUrl is relative or missing (e.g. text file placeholder), we can't deep copy easily
            // But assuming Vercel Blob:
            let newDownloadUrl = original.downloadUrl;
            let newStoredFilename = original.storedFilename;

            // Only attempt blob copy if it looks like a remote URL (Vercel Blob)
            if (original.downloadUrl && original.downloadUrl.startsWith('http')) {
                try {
                    const newBlobPath = `files/${newId}_${original.name}`;
                    const copyResult = await copy(original.downloadUrl, newBlobPath, {
                        access: 'public',
                        token: process.env.BLOB_READ_WRITE_TOKEN
                    });
                    newDownloadUrl = copyResult.url;
                    newStoredFilename = newBlobPath;
                } catch (blobErr) {
                    console.error(`Failed to copy blob for file ${fileId}:`, blobErr);
                    // Fallback? Or fail? 
                    // If blob copy fails, we probably shouldn't create the file record to avoid "ghost" files
                    // But maybe we continue with shared blob as fallback?
                    // User explicitly requested NEW BLOB. So failing is better than lying.
                    continue; // Skip this file
                }
            }

            // Create new record pointing to NEW blob
            await query.run(
                'INSERT INTO files (id, spaceId, name, storedFilename, type, mimeType, size, uploadedBy, downloadUrl, folderId, createdAt) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                [newId, original.spaceId, original.name, newStoredFilename, original.type, original.mimeType, original.size, userId, newDownloadUrl, folderId || null, createdAt]
            );

            copiedFiles.push(newId);
        }

        res.json({ success: true, copied: copiedFiles.length, newIds: copiedFiles });
    } catch (err) {
        console.error('Copy files error:', err);
        res.status(500).json({ error: 'Failed to copy files' });
    }
});

app.post('/api/files/:spaceId', async (req, res) => {
    try {
        const { name, fileData, uploadedBy, folderId } = req.body;
        if (!name || !fileData) return res.status(400).json({ error: 'File name and data required' });

        const matches = fileData.match(/^data:(.+);base64,(.+)$/);
        if (!matches) return res.status(400).json({ error: 'Invalid file format' });

        const mimeType = matches[1];
        const base64Data = matches[2];
        const buffer = Buffer.from(base64Data, 'base64');
        const extension = name.split('.').pop() || 'bin';
        const blobFilename = `files/${uuidv4()}_${name}`;

        // Calculate size
        let size = buffer.length + ' B';
        if (buffer.length > 1024 * 1024) size = (buffer.length / (1024 * 1024)).toFixed(1) + ' MB';
        else if (buffer.length > 1024) size = (buffer.length / 1024).toFixed(1) + ' KB';

        // Upload to Vercel Blob
        const blob = await put(blobFilename, buffer, {
            access: 'public',
            contentType: mimeType,
            contentDisposition: `attachment; filename="${name}"`
        });

        const id = uuidv4();
        const createdAt = new Date().toISOString();

        await query.run(
            'INSERT INTO files (id, spaceId, name, storedFilename, type, mimeType, size, uploadedBy, downloadUrl, folderId, createdAt) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
            [id, req.params.spaceId, name, blobFilename, extension.toUpperCase(), mimeType, size, uploadedBy, blob.url, folderId || null, createdAt]
        );

        res.status(201).json({ id, spaceId: req.params.spaceId, name, storedFilename: blobFilename, type: extension.toUpperCase(), mimeType, size, uploadedBy, downloadUrl: blob.url, folderId: folderId || null, createdAt });
    } catch (err) {
        console.error('File upload error:', err);
        res.status(500).json({ error: 'Failed to upload file' });
    }
});

// Create a link file (no actual file upload, just store URL)
app.post('/api/files/:spaceId/link', async (req, res) => {
    try {
        const { name, url, uploadedBy, folderId } = req.body;
        if (!name || !url) return res.status(400).json({ error: 'Name and URL are required' });

        // Validate URL format
        try {
            new URL(url);
        } catch (e) {
            return res.status(400).json({ error: 'Invalid URL format' });
        }

        const id = uuidv4();
        const createdAt = new Date().toISOString();

        await query.run(
            'INSERT INTO files (id, spaceId, name, storedFilename, type, mimeType, size, uploadedBy, downloadUrl, folderId, createdAt) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
            [id, req.params.spaceId, name, null, 'LINK', 'text/uri-list', null, uploadedBy, url, folderId || null, createdAt]
        );

        res.status(201).json({
            id,
            spaceId: req.params.spaceId,
            name,
            storedFilename: null,
            type: 'LINK',
            mimeType: 'text/uri-list',
            size: null,
            uploadedBy,
            downloadUrl: url,
            folderId: folderId || null,
            createdAt
        });
    } catch (err) {
        console.error('Create link error:', err);
        res.status(500).json({ error: 'Failed to create link' });
    }
});

app.get('/api/files/:fileId/download', async (req, res) => {
    try {
        const file = await query.get('SELECT * FROM files WHERE id = ?', [req.params.fileId]);
        if (!file || !file.downloadUrl) return res.status(404).json({ error: 'File not found' });

        // Proxy the download to force correct headers
        const response = await fetch(file.downloadUrl);
        if (!response.ok) throw new Error(`Failed to fetch file: ${response.statusText}`);

        res.setHeader('Content-Disposition', `attachment; filename="${file.name}"`);
        res.setHeader('Content-Type', file.mimeType || 'application/octet-stream');

        // Pipe the body stream to the response
        const { Readable } = require('stream');
        // Convert web stream to node stream
        if (response.body) {
            const reader = response.body.getReader();
            const stream = new Readable({
                async read() {
                    const { done, value } = await reader.read();
                    if (done) {
                        this.push(null);
                    } else {
                        this.push(Buffer.from(value));
                    }
                }
            });
            stream.pipe(res);
        } else {
            res.end();
        }
    } catch (err) {
        console.error('File download error:', err);
        res.status(500).json({ error: 'Failed to download file' });
    }
});

// Move file(s) to a different folder
app.put('/api/files/move', async (req, res) => {
    try {
        const { fileIds, folderId, userId } = req.body;
        if (!fileIds || !Array.isArray(fileIds) || fileIds.length === 0) {
            return res.status(400).json({ error: 'File IDs array required' });
        }

        // Update all files to new folder
        for (const fileId of fileIds) {
            await query.run('UPDATE files SET folderId = ? WHERE id = ?', [folderId || null, fileId]);
        }

        res.json({ success: true, moved: fileIds.length });
    } catch (err) {
        console.error('Move files error:', err);
        res.status(500).json({ error: 'Failed to move files' });
    }
});

// Rename file
app.put('/api/files/:fileId', async (req, res) => {
    try {
        const { name, userId } = req.body;
        if (!name || !userId) return res.status(400).json({ error: 'Name and User ID required' });

        const file = await query.get('SELECT * FROM files WHERE id = ?', [req.params.fileId]);
        if (!file) return res.status(404).json({ error: 'File not found' });

        // Permission check
        const space = await query.get('SELECT ownerId FROM spaces WHERE id = ?', [file.spaceId]);
        const membership = await query.get('SELECT role FROM space_members WHERE spaceId = ? AND userId = ?', [file.spaceId, userId]);

        const isUploader = file.uploadedBy === userId;
        const isOwner = space?.ownerId === userId;
        const isAdmin = membership?.role === 'Admin' || membership?.role === 'Owner';

        if (!isUploader && !isOwner && !isAdmin) {
            return res.status(403).json({ error: 'Permission denied' });
        }

        await query.run('UPDATE files SET name = ? WHERE id = ?', [name.trim(), req.params.fileId]);
        res.json({ success: true, name: name.trim() });
    } catch (err) {
        console.error('File rename error:', err);
        res.status(500).json({ error: 'Failed to rename file' });
    }
});

app.delete('/api/files/:fileId', async (req, res) => {
    try {
        const { userId } = req.body;
        if (!userId) return res.status(400).json({ error: 'User ID required' });

        const file = await query.get('SELECT * FROM files WHERE id = ?', [req.params.fileId]);
        if (!file) return res.status(404).json({ error: 'File not found' });

        // Permission check
        const space = await query.get('SELECT ownerId FROM spaces WHERE id = ?', [file.spaceId]);
        const membership = await query.get('SELECT role FROM space_members WHERE spaceId = ? AND userId = ?', [file.spaceId, userId]);

        const isUploader = file.uploadedBy === userId;
        const isOwner = space?.ownerId === userId;
        const isAdmin = membership?.role === 'Admin' || membership?.role === 'Owner';

        if (!isUploader && !isOwner && !isAdmin) {
            return res.status(403).json({ error: 'Permission denied' });
        }

        // Delete from Vercel Blob
        if (file.downloadUrl && file.downloadUrl.includes('blob.vercel-storage.com')) {
            try { await del(file.downloadUrl); } catch (e) { /* ignore */ }
        }

        await query.run('DELETE FROM files WHERE id = ?', [req.params.fileId]);
        res.json({ success: true });
    } catch (err) {
        console.error('File delete error:', err);
        res.status(500).json({ error: 'Failed to delete file' });
    }
});

// ============ FAVORITES ROUTES ============
app.get('/api/users/:userId/favorites', async (req, res) => {
    try {
        const favorites = await query.all('SELECT spaceId FROM user_favorites WHERE userId = ?', [req.params.userId]);
        res.json(favorites.map(f => f.spaceId));
    } catch (err) {
        console.error('Get favorites error:', err);
        res.status(500).json({ error: 'Failed to get favorites' });
    }
});

app.post('/api/users/:userId/favorites/:spaceId', async (req, res) => {
    try {
        await query.run(
            'INSERT INTO user_favorites (id, userId, spaceId, createdAt) VALUES (?, ?, ?, ?)',
            [uuidv4(), req.params.userId, req.params.spaceId, new Date().toISOString()]
        );
        res.json({ success: true });
    } catch {
        res.json({ success: true }); // Already exists
    }
});

app.delete('/api/users/:userId/favorites/:spaceId', async (req, res) => {
    try {
        await query.run('DELETE FROM user_favorites WHERE userId = ? AND spaceId = ?', [req.params.userId, req.params.spaceId]);
        res.json({ success: true });
    } catch (err) {
        console.error('Delete favorite error:', err);
        res.status(500).json({ error: 'Failed to delete favorite' });
    }
});

app.post('/api/users/:userId/favorites/:spaceId/toggle', async (req, res) => {
    try {
        const existing = await query.get('SELECT id FROM user_favorites WHERE userId = ? AND spaceId = ?', [req.params.userId, req.params.spaceId]);
        if (existing) {
            await query.run('DELETE FROM user_favorites WHERE id = ?', [existing.id]);
            res.json({ isFavorite: false });
        } else {
            await query.run('INSERT INTO user_favorites (id, userId, spaceId, createdAt) VALUES (?, ?, ?, ?)', [uuidv4(), req.params.userId, req.params.spaceId, new Date().toISOString()]);
            res.json({ isFavorite: true });
        }
    } catch (err) {
        console.error('Toggle favorite error:', err);
        res.status(500).json({ error: 'Failed to toggle favorite' });
    }
});

// ============ START SERVER ============
async function startServer() {
    try {
        await initDatabase();
        app.listen(PORT, () => {
            console.log(`🚀 Server running on http://localhost:${PORT}`);
            console.log(`☁️  Using Turso cloud database`);
        });
    } catch (error) {
        console.error('Failed to start server:', error);
        process.exit(1);
    }
}

startServer();
