require('dotenv').config();
const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const { put, del } = require('@vercel/blob');
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

app.post('/api/auth/login', async (req, res) => {
    try {
        let { email, password } = req.body;

        // Trim and normalize
        email = email?.trim() || '';
        const emailNormalized = normalizeEmail(email);

        // Try to find user by normalized email or original email (for backwards compat)
        const user = await query.get(
            'SELECT * FROM users WHERE (emailNormalized = ? OR email = ?) AND password = ?',
            [emailNormalized, email.toLowerCase(), password]
        );

        if (!user) return res.status(401).json({ error: 'Invalid credentials' });

        const { password: _, emailNormalized: __, usernameNormalized: ___, ...userWithoutSensitive } = user;
        res.json(userWithoutSensitive);
    } catch (err) {
        console.error('Login error:', err);
        res.status(500).json({ error: 'Login failed' });
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
                fileCount: files.length
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

        res.status(201).json({ ...newSpace, thumbnail: newSpace.thumbnailGradient });
    } catch (err) {
        console.error('Create space error:', err);
        res.status(500).json({ error: 'Failed to create space' });
    }
});

app.get('/api/spaces/:id', async (req, res) => {
    try {
        const space = await query.get('SELECT * FROM spaces WHERE id = ?', [req.params.id]);
        if (!space) return res.status(404).json({ error: 'Space not found' });
        res.json({ ...space, thumbnail: space.thumbnailGradient || space.thumbnailImage });
    } catch (err) {
        console.error('Get space error:', err);
        res.status(500).json({ error: 'Failed to get space' });
    }
});

app.put('/api/spaces/:id', async (req, res) => {
    try {
        const space = await query.get('SELECT * FROM spaces WHERE id = ?', [req.params.id]);
        if (!space) return res.status(404).json({ error: 'Space not found' });

        const { name, description, category, thumbnail } = req.body;
        await query.run(
            'UPDATE spaces SET name = ?, description = ?, category = ?, thumbnailGradient = ? WHERE id = ?',
            [name || space.name, description !== undefined ? description : space.description, category || space.category, thumbnail || space.thumbnailGradient, req.params.id]
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
        // Get files first (before cascade deletes them from DB)
        const files = await query.all('SELECT downloadUrl FROM files WHERE spaceId = ?', [req.params.id]);

        const result = await query.run('DELETE FROM spaces WHERE id = ?', [req.params.id]);
        if (result.changes === 0) return res.status(404).json({ error: 'Space not found' });

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
        await query.run('DELETE FROM space_members WHERE id = ?', [req.params.memberId]);
        res.json({ success: true });
    } catch (err) {
        console.error('Delete member error:', err);
        res.status(500).json({ error: 'Failed to delete member' });
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
});

// ============ INVITE ROUTES ============
app.post('/api/spaces/:spaceId/invite', async (req, res) => {
    try {
        const { emails, inviterId, inviterName } = req.body;
        if (!emails || !Array.isArray(emails)) return res.status(400).json({ error: 'Emails required' });

        const space = await query.get('SELECT name FROM spaces WHERE id = ?', [req.params.spaceId]);
        if (!space) return res.status(404).json({ error: 'Space not found' });

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

app.post('/api/invites/:inviteId/accept', async (req, res) => {
    try {
        const invite = await query.get('SELECT * FROM space_invites WHERE id = ?', [req.params.inviteId]);
        if (!invite) return res.status(404).json({ error: 'Invite not found' });
        if (invite.status !== 'pending') return res.status(400).json({ error: 'Invite already processed' });

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

// ============ MESSAGES ROUTES ============
app.get('/api/messages/:spaceId', async (req, res) => {
    try {
        const messages = await query.all(`
            SELECT m.*, u.name as senderName, u.avatarColor, u.avatarImage
            FROM messages m
            LEFT JOIN users u ON m.senderId = u.id
            WHERE m.spaceId = ?
            ORDER BY m.createdAt ASC
        `, [req.params.spaceId]);

        const transformed = messages.map(m => ({
            id: m.id,
            spaceId: m.spaceId,
            senderId: m.senderId,
            sender: m.type === 'system' ? 'System' : (m.senderName || 'Unknown User'),
            text: m.text,
            type: m.type,
            mentions: m.mentions ? JSON.parse(m.mentions) : [],
            time: new Date(m.createdAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
            createdAt: m.createdAt,
            avatarColor: m.avatarColor || '#9ca3af',
            avatarImage: m.avatarImage
        }));

        res.json(transformed);
    } catch (err) {
        console.error('Get messages error:', err);
        res.status(500).json({ error: 'Failed to get messages' });
    }
});

app.post('/api/messages/:spaceId', async (req, res) => {
    try {
        const { senderId, text, type, mentions } = req.body;
        const id = uuidv4();
        const createdAt = new Date().toISOString();

        await query.run(
            'INSERT INTO messages (id, spaceId, senderId, text, type, mentions, createdAt) VALUES (?, ?, ?, ?, ?, ?, ?)',
            [id, req.params.spaceId, senderId, text, type || 'user', mentions ? JSON.stringify(mentions) : null, createdAt]
        );

        const sender = await query.get('SELECT name, avatarColor, avatarImage FROM users WHERE id = ?', [senderId]);
        res.status(201).json({
            id,
            spaceId: req.params.spaceId,
            senderId,
            sender: sender?.name || 'User',
            text,
            type: type || 'user',
            mentions: mentions || [],
            time: new Date(createdAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
            createdAt,
            avatarColor: sender?.avatarColor || '#ec4899',
            avatarImage: sender?.avatarImage
        });
    } catch (err) {
        console.error('Send message error:', err);
        res.status(500).json({ error: 'Failed to send message' });
    }
});

// ============ FILES ROUTES ============
app.get('/api/files/:spaceId', async (req, res) => {
    try {
        const files = await query.all(`
            SELECT f.*, u.name as uploaderName
            FROM files f
            LEFT JOIN users u ON f.uploadedBy = u.id
            WHERE f.spaceId = ?
        `, [req.params.spaceId]);

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

app.post('/api/files/:spaceId', async (req, res) => {
    try {
        const { name, fileData, uploadedBy } = req.body;
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
            'INSERT INTO files (id, spaceId, name, storedFilename, type, mimeType, size, uploadedBy, downloadUrl, createdAt) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
            [id, req.params.spaceId, name, blobFilename, extension.toUpperCase(), mimeType, size, uploadedBy, blob.url, createdAt]
        );

        res.status(201).json({ id, spaceId: req.params.spaceId, name, storedFilename: blobFilename, type: extension.toUpperCase(), mimeType, size, uploadedBy, downloadUrl: blob.url, createdAt });
    } catch (err) {
        console.error('File upload error:', err);
        res.status(500).json({ error: 'Failed to upload file' });
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
