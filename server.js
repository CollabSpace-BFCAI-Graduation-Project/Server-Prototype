const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const db = require('./db');

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

// ============ AUTH ROUTES ============
app.post('/api/auth/register', (req, res) => {
    const { name, username, email, password } = req.body;

    if (!name || !username || !email || !password) {
        return res.status(400).json({ error: 'All fields are required' });
    }

    if (!/^[a-z0-9_]{3,20}$/.test(username)) {
        return res.status(400).json({ error: 'Username must be 3-20 chars, lowercase, numbers, underscores only' });
    }

    // Check existing
    const existingEmail = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
    if (existingEmail) return res.status(400).json({ error: 'Email already registered' });

    const existingUsername = db.prepare('SELECT id FROM users WHERE username = ?').get(username);
    if (existingUsername) return res.status(400).json({ error: 'Username already taken' });

    const colors = ['#3b82f6', '#10b981', '#f59e0b', '#ec4899', '#8b5cf6', '#ef4444', '#14b8a6', '#f97316'];
    const newUser = {
        id: uuidv4(),
        name,
        username,
        email,
        password,
        avatarColor: colors[Math.floor(Math.random() * colors.length)],
        avatarImage: null,
        bio: '',
        createdAt: new Date().toISOString()
    };

    db.prepare(`
        INSERT INTO users (id, name, username, email, password, avatarColor, avatarImage, bio, createdAt)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(newUser.id, newUser.name, newUser.username, newUser.email, newUser.password, newUser.avatarColor, newUser.avatarImage, newUser.bio, newUser.createdAt);

    const { password: _, ...userWithoutPassword } = newUser;
    res.status(201).json(userWithoutPassword);
});

app.post('/api/auth/login', (req, res) => {
    const { email, password } = req.body;
    const user = db.prepare('SELECT * FROM users WHERE email = ? AND password = ?').get(email, password);

    if (!user) return res.status(401).json({ error: 'Invalid credentials' });

    const { password: _, ...userWithoutPassword } = user;
    res.json(userWithoutPassword);
});

// ============ USER ROUTES ============
app.get('/api/users', (req, res) => {
    const users = db.prepare('SELECT id, name, username, email, avatarColor, avatarImage, bio, createdAt FROM users').all();
    res.json(users);
});

app.get('/api/users/:id', (req, res) => {
    const user = db.prepare('SELECT id, name, username, email, avatarColor, avatarImage, bio, createdAt FROM users WHERE id = ?').get(req.params.id);
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json(user);
});

app.put('/api/users/:id', (req, res) => {
    const { name, username, email, bio } = req.body;
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.params.id);
    if (!user) return res.status(404).json({ error: 'User not found' });

    db.prepare('UPDATE users SET name = ?, username = ?, email = ?, bio = ? WHERE id = ?')
        .run(name || user.name, username || user.username, email || user.email, bio !== undefined ? bio : user.bio, req.params.id);

    const updated = db.prepare('SELECT id, name, username, email, avatarColor, avatarImage, bio, createdAt FROM users WHERE id = ?').get(req.params.id);
    res.json(updated);
});

app.delete('/api/users/:id', (req, res) => {
    const result = db.prepare('DELETE FROM users WHERE id = ?').run(req.params.id);
    if (result.changes === 0) return res.status(404).json({ error: 'User not found' });
    res.json({ success: true });
});

// Avatar upload
app.post('/api/users/:id/avatar', (req, res) => {
    const { imageData } = req.body;
    if (!imageData) return res.status(400).json({ error: 'No image data provided' });

    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.params.id);
    if (!user) return res.status(404).json({ error: 'User not found' });

    // Delete old avatar if exists
    if (user.avatarImage) {
        const oldPath = path.join(__dirname, user.avatarImage);
        if (fs.existsSync(oldPath)) fs.unlinkSync(oldPath);
    }

    // Save new avatar
    const matches = imageData.match(/^data:image\/(\w+);base64,(.+)$/);
    if (!matches) return res.status(400).json({ error: 'Invalid image format' });

    const ext = matches[1] === 'jpeg' ? 'jpeg' : matches[1];
    const base64Data = matches[2];
    const filename = `avatar_${req.params.id}_${Date.now()}.${ext}`;
    const filepath = path.join(IMAGES_DIR, filename);
    fs.writeFileSync(filepath, base64Data, 'base64');

    const avatarImage = `/images/${filename}`;
    db.prepare('UPDATE users SET avatarImage = ? WHERE id = ?').run(avatarImage, req.params.id);

    const updated = db.prepare('SELECT id, name, username, email, avatarColor, avatarImage, bio, createdAt FROM users WHERE id = ?').get(req.params.id);
    res.json(updated);
});

app.delete('/api/users/:id/avatar', (req, res) => {
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.params.id);
    if (!user) return res.status(404).json({ error: 'User not found' });

    if (user.avatarImage) {
        const oldPath = path.join(__dirname, user.avatarImage);
        if (fs.existsSync(oldPath)) fs.unlinkSync(oldPath);
    }

    db.prepare('UPDATE users SET avatarImage = NULL WHERE id = ?').run(req.params.id);
    const updated = db.prepare('SELECT id, name, username, email, avatarColor, avatarImage, bio, createdAt FROM users WHERE id = ?').get(req.params.id);
    res.json(updated);
});

// ============ SPACES ROUTES ============
app.get('/api/spaces', (req, res) => {
    let spaces;
    if (req.query.userId) {
        // Get spaces where user is a member, with owner info
        spaces = db.prepare(`
            SELECT s.*, u.name as ownerName
            FROM spaces s
            INNER JOIN space_members sm ON s.id = sm.spaceId
            LEFT JOIN users u ON s.ownerId = u.id
            WHERE sm.userId = ?
            ORDER BY s.createdAt DESC
        `).all(req.query.userId);
    } else {
        spaces = db.prepare(`
            SELECT s.*, u.name as ownerName
            FROM spaces s
            LEFT JOIN users u ON s.ownerId = u.id
            ORDER BY s.createdAt DESC
        `).all();
    }

    // Enrich with members and files
    const enriched = spaces.map(space => {
        const members = db.prepare(`
            SELECT sm.*, u.name, u.username, u.avatarColor, u.avatarImage
            FROM space_members sm
            LEFT JOIN users u ON sm.userId = u.id
            WHERE sm.spaceId = ?
        `).all(space.id);

        const files = db.prepare(`
            SELECT f.*, u.name as uploaderName
            FROM files f
            LEFT JOIN users u ON f.uploadedBy = u.id
            WHERE f.spaceId = ?
        `).all(space.id);

        return {
            ...space,
            // Map thumbnailGradient to thumbnail for frontend compatibility
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
                avatarImage: m.avatarImage ? `http://localhost:${PORT}${m.avatarImage}` : null,
                joinedAt: m.joinedAt
            })),
            memberCount: members.length,
            files,
            fileCount: files.length
        };
    });

    res.json(enriched);
});

app.post('/api/spaces', (req, res) => {
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

    db.prepare(`
        INSERT INTO spaces (id, name, thumbnailGradient, thumbnailImage, category, description, ownerId, createdAt)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).run(newSpace.id, newSpace.name, newSpace.thumbnailGradient, newSpace.thumbnailImage, newSpace.category, newSpace.description, newSpace.ownerId, newSpace.createdAt);

    // Add owner as member
    db.prepare(`
        INSERT INTO space_members (id, spaceId, userId, role, joinedAt)
        VALUES (?, ?, ?, 'Owner', ?)
    `).run(uuidv4(), newSpace.id, newSpace.ownerId, newSpace.createdAt);

    res.status(201).json({ ...newSpace, thumbnail: newSpace.thumbnailGradient });
});

app.get('/api/spaces/:id', (req, res) => {
    const space = db.prepare('SELECT * FROM spaces WHERE id = ?').get(req.params.id);
    if (!space) return res.status(404).json({ error: 'Space not found' });
    res.json({ ...space, thumbnail: space.thumbnailGradient || space.thumbnailImage });
});

app.put('/api/spaces/:id', (req, res) => {
    const space = db.prepare('SELECT * FROM spaces WHERE id = ?').get(req.params.id);
    if (!space) return res.status(404).json({ error: 'Space not found' });

    const { name, description, category, thumbnail } = req.body;
    db.prepare(`
        UPDATE spaces SET name = ?, description = ?, category = ?, thumbnailGradient = ? WHERE id = ?
    `).run(name || space.name, description !== undefined ? description : space.description, category || space.category, thumbnail || space.thumbnailGradient, req.params.id);

    const updated = db.prepare('SELECT * FROM spaces WHERE id = ?').get(req.params.id);
    res.json({ ...updated, thumbnail: updated.thumbnailGradient || updated.thumbnailImage });
});

app.delete('/api/spaces/:id', (req, res) => {
    // Get files first (before cascade deletes them from DB)
    const files = db.prepare('SELECT storedFilename FROM files WHERE spaceId = ?').all(req.params.id);

    const result = db.prepare('DELETE FROM spaces WHERE id = ?').run(req.params.id);
    if (result.changes === 0) return res.status(404).json({ error: 'Space not found' });

    // Delete physical files from disk
    files.forEach(f => {
        if (f.storedFilename) {
            const filepath = path.join(UPLOADS_DIR, f.storedFilename);
            if (fs.existsSync(filepath)) {
                try { fs.unlinkSync(filepath); } catch (e) { /* ignore */ }
            }
        }
    });

    res.json({ success: true });
});

// ============ SPACE MEMBERS ROUTES ============
app.get('/api/spaces/:spaceId/members', (req, res) => {
    const members = db.prepare(`
        SELECT sm.*, u.name, u.username, u.avatarColor, u.avatarImage, u.email
        FROM space_members sm
        LEFT JOIN users u ON sm.userId = u.id
        WHERE sm.spaceId = ?
    `).all(req.params.spaceId);

    const enriched = members.map(m => ({
        id: m.id,
        odId: m.userId,
        userId: m.userId,
        name: m.name,
        username: m.username,
        email: m.email,
        role: m.role,
        avatarColor: m.avatarColor,
        avatarImage: m.avatarImage ? `http://localhost:${PORT}${m.avatarImage}` : null,
        joinedAt: m.joinedAt
    }));

    res.json(enriched);
});

app.get('/api/users/:userId/spaces', (req, res) => {
    const spaces = db.prepare(`
        SELECT s.* FROM spaces s
        INNER JOIN space_members sm ON s.id = sm.spaceId
        WHERE sm.userId = ?
    `).all(req.params.userId);

    res.json(spaces.map(s => ({ ...s, thumbnail: s.thumbnailGradient || s.thumbnailImage })));
});

app.post('/api/spaces/:spaceId/members', (req, res) => {
    const { userId, role } = req.body;
    const id = uuidv4();
    const joinedAt = new Date().toISOString();

    try {
        db.prepare(`
            INSERT INTO space_members (id, spaceId, userId, role, joinedAt)
            VALUES (?, ?, ?, ?, ?)
        `).run(id, req.params.spaceId, userId, role || 'Member', joinedAt);
        res.status(201).json({ id, spaceId: req.params.spaceId, userId, role: role || 'Member', joinedAt });
    } catch (err) {
        res.status(400).json({ error: 'User already a member' });
    }
});

app.put('/api/spaces/:spaceId/members/:memberId', (req, res) => {
    const { role } = req.body;
    db.prepare('UPDATE space_members SET role = ? WHERE id = ?').run(role, req.params.memberId);
    res.json({ success: true });
});

app.delete('/api/spaces/:spaceId/members/:memberId', (req, res) => {
    db.prepare('DELETE FROM space_members WHERE id = ?').run(req.params.memberId);
    res.json({ success: true });
});

app.post('/api/spaces/:spaceId/leave', (req, res) => {
    const { userId } = req.body;
    db.prepare('DELETE FROM space_members WHERE spaceId = ? AND userId = ?').run(req.params.spaceId, userId);
    res.json({ success: true });
});

// ============ INVITE ROUTES ============
app.post('/api/spaces/:spaceId/invite', (req, res) => {
    const { emails, inviterId, inviterName } = req.body;
    if (!emails || !Array.isArray(emails)) return res.status(400).json({ error: 'Emails required' });

    const space = db.prepare('SELECT name FROM spaces WHERE id = ?').get(req.params.spaceId);
    if (!space) return res.status(404).json({ error: 'Space not found' });

    let invited = 0;
    emails.forEach(email => {
        const user = db.prepare('SELECT id FROM users WHERE LOWER(email) = LOWER(?)').get(email);
        if (!user) return;

        // Check if already member
        const isMember = db.prepare('SELECT id FROM space_members WHERE spaceId = ? AND userId = ?').get(req.params.spaceId, user.id);
        if (isMember) return;

        // Check if already invited
        const hasInvite = db.prepare('SELECT id FROM space_invites WHERE spaceId = ? AND userId = ? AND status = ?').get(req.params.spaceId, user.id, 'pending');
        if (hasInvite) return;

        const inviteId = uuidv4();
        db.prepare(`
            INSERT INTO space_invites (id, spaceId, userId, inviterId, status, createdAt)
            VALUES (?, ?, ?, ?, 'pending', ?)
        `).run(inviteId, req.params.spaceId, user.id, inviterId, new Date().toISOString());

        // Create notification
        db.prepare(`
            INSERT INTO notifications (id, userId, type, actorId, targetType, targetId, message, read, createdAt)
            VALUES (?, ?, 'invite', ?, 'space', ?, ?, 0, ?)
        `).run(uuidv4(), user.id, inviterId, req.params.spaceId, `${inviterName || 'Someone'} invited you to join ${space.name}`, new Date().toISOString());

        invited++;
    });

    res.json({ success: true, invited });
});

app.get('/api/users/:userId/invites', (req, res) => {
    const invites = db.prepare(`
        SELECT si.*, s.name as spaceName, u.name as inviterName
        FROM space_invites si
        LEFT JOIN spaces s ON si.spaceId = s.id
        LEFT JOIN users u ON si.inviterId = u.id
        WHERE si.userId = ? AND si.status = 'pending'
    `).all(req.params.userId);
    res.json(invites);
});

app.post('/api/invites/:inviteId/accept', (req, res) => {
    const invite = db.prepare('SELECT * FROM space_invites WHERE id = ?').get(req.params.inviteId);
    if (!invite) return res.status(404).json({ error: 'Invite not found' });
    if (invite.status !== 'pending') return res.status(400).json({ error: 'Invite already processed' });

    // Update invite
    db.prepare('UPDATE space_invites SET status = ?, respondedAt = ? WHERE id = ?')
        .run('accepted', new Date().toISOString(), req.params.inviteId);

    // Add as member
    db.prepare(`
        INSERT INTO space_members (id, spaceId, userId, role, joinedAt)
        VALUES (?, ?, ?, 'Member', ?)
    `).run(uuidv4(), invite.spaceId, invite.userId, new Date().toISOString());

    // Notify inviter
    const space = db.prepare('SELECT name FROM spaces WHERE id = ?').get(invite.spaceId);
    const user = db.prepare('SELECT name FROM users WHERE id = ?').get(invite.userId);
    db.prepare(`
        INSERT INTO notifications (id, userId, type, actorId, targetType, targetId, message, read, createdAt)
        VALUES (?, ?, 'system', ?, 'space', ?, ?, 0, ?)
    `).run(uuidv4(), invite.inviterId, invite.userId, invite.spaceId, `${user?.name || 'Someone'} accepted your invite to join ${space?.name || 'a space'}`, new Date().toISOString());

    res.json({ success: true });
});

app.post('/api/invites/:inviteId/decline', (req, res) => {
    db.prepare('UPDATE space_invites SET status = ?, respondedAt = ? WHERE id = ?')
        .run('declined', new Date().toISOString(), req.params.inviteId);
    res.json({ success: true });
});

// ============ NOTIFICATIONS ROUTES ============
app.get('/api/notifications', (req, res) => {
    let notifications;
    if (req.query.userId) {
        notifications = db.prepare(`
            SELECT n.*, u.name as actorName, u.avatarColor as actorAvatarColor, u.avatarImage as actorAvatarImage
            FROM notifications n
            LEFT JOIN users u ON n.actorId = u.id
            WHERE n.userId = ?
            ORDER BY n.createdAt DESC
        `).all(req.query.userId);
    } else {
        notifications = db.prepare('SELECT * FROM notifications ORDER BY createdAt DESC').all();
    }

    // Transform for frontend compatibility
    const transformed = notifications.map(n => {
        // For invite notifications, look up the actual invite ID
        let inviteId = null;
        if (n.type === 'invite' && n.targetType === 'space') {
            const invite = db.prepare(
                'SELECT id FROM space_invites WHERE spaceId = ? AND userId = ? AND status = ?'
            ).get(n.targetId, n.userId, 'pending');
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
    });

    res.json(transformed);
});

app.post('/api/notifications', (req, res) => {
    const { userId, type, actorId, targetType, targetId, message } = req.body;
    const id = uuidv4();
    db.prepare(`
        INSERT INTO notifications (id, userId, type, actorId, targetType, targetId, message, read, createdAt)
        VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?)
    `).run(id, userId, type, actorId, targetType, targetId, message, new Date().toISOString());
    res.status(201).json({ id });
});

app.put('/api/notifications/:id/read', (req, res) => {
    db.prepare('UPDATE notifications SET read = 1 WHERE id = ?').run(req.params.id);
    res.json({ success: true });
});

app.put('/api/notifications/read-all', (req, res) => {
    db.prepare('UPDATE notifications SET read = 1').run();
    res.json({ success: true });
});

// ============ MESSAGES ROUTES ============
app.get('/api/messages/:spaceId', (req, res) => {
    const messages = db.prepare(`
        SELECT m.*, u.name as senderName, u.avatarColor, u.avatarImage
        FROM messages m
        LEFT JOIN users u ON m.senderId = u.id
        WHERE m.spaceId = ?
        ORDER BY m.createdAt ASC
    `).all(req.params.spaceId);

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
        avatarImage: m.avatarImage ? `http://localhost:${PORT}${m.avatarImage}` : null
    }));

    res.json(transformed);
});

app.post('/api/messages/:spaceId', (req, res) => {
    const { senderId, text, type, mentions } = req.body;
    const id = uuidv4();
    const createdAt = new Date().toISOString();

    db.prepare(`
        INSERT INTO messages (id, spaceId, senderId, text, type, mentions, createdAt)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(id, req.params.spaceId, senderId, text, type || 'user', mentions ? JSON.stringify(mentions) : null, createdAt);

    const sender = db.prepare('SELECT name, avatarColor, avatarImage FROM users WHERE id = ?').get(senderId);
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
        avatarImage: sender?.avatarImage ? `http://localhost:${PORT}${sender.avatarImage}` : null
    });
});

// ============ FILES ROUTES ============
app.get('/api/files/:spaceId', (req, res) => {
    const files = db.prepare(`
        SELECT f.*, u.name as uploaderName
        FROM files f
        LEFT JOIN users u ON f.uploadedBy = u.id
        WHERE f.spaceId = ?
    `).all(req.params.spaceId);

    const enriched = files.map(f => ({
        ...f,
        uploaderName: f.uploaderName || 'Unknown User'
    }));

    res.json(enriched);
});

app.post('/api/files/:spaceId', (req, res) => {
    const { name, fileData, uploadedBy } = req.body;
    if (!name || !fileData) return res.status(400).json({ error: 'File name and data required' });

    const matches = fileData.match(/^data:(.+);base64,(.+)$/);
    if (!matches) return res.status(400).json({ error: 'Invalid file format' });

    const mimeType = matches[1];
    const base64Data = matches[2];
    const extension = name.split('.').pop() || 'bin';
    const storedFilename = `${uuidv4()}.${extension}`;
    const filepath = path.join(UPLOADS_DIR, storedFilename);

    fs.writeFileSync(filepath, base64Data, 'base64');

    const stats = fs.statSync(filepath);
    let size = stats.size + ' B';
    if (stats.size > 1024 * 1024) size = (stats.size / (1024 * 1024)).toFixed(1) + ' MB';
    else if (stats.size > 1024) size = (stats.size / 1024).toFixed(1) + ' KB';

    const id = uuidv4();
    const downloadUrl = `/uploads/${storedFilename}`;
    const createdAt = new Date().toISOString();

    db.prepare(`
        INSERT INTO files (id, spaceId, name, storedFilename, type, mimeType, size, uploadedBy, downloadUrl, createdAt)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(id, req.params.spaceId, name, storedFilename, extension.toUpperCase(), mimeType, size, uploadedBy, downloadUrl, createdAt);

    res.status(201).json({ id, spaceId: req.params.spaceId, name, storedFilename, type: extension.toUpperCase(), mimeType, size, uploadedBy, downloadUrl, createdAt });
});

app.get('/api/files/:fileId/download', (req, res) => {
    const file = db.prepare('SELECT * FROM files WHERE id = ?').get(req.params.fileId);
    if (!file || !file.storedFilename) return res.status(404).json({ error: 'File not found' });

    const filepath = path.join(UPLOADS_DIR, file.storedFilename);
    if (!fs.existsSync(filepath)) return res.status(404).json({ error: 'File not found on disk' });

    res.download(filepath, file.name);
});

app.delete('/api/files/:fileId', (req, res) => {
    const { userId } = req.body;
    if (!userId) return res.status(400).json({ error: 'User ID required' });

    const file = db.prepare('SELECT * FROM files WHERE id = ?').get(req.params.fileId);
    if (!file) return res.status(404).json({ error: 'File not found' });

    // Permission check
    const space = db.prepare('SELECT ownerId FROM spaces WHERE id = ?').get(file.spaceId);
    const membership = db.prepare('SELECT role FROM space_members WHERE spaceId = ? AND userId = ?').get(file.spaceId, userId);

    const isUploader = file.uploadedBy === userId;
    const isOwner = space?.ownerId === userId;
    const isAdmin = membership?.role === 'Admin' || membership?.role === 'Owner';

    if (!isUploader && !isOwner && !isAdmin) {
        return res.status(403).json({ error: 'Permission denied' });
    }

    // Delete from disk
    if (file.storedFilename) {
        const filepath = path.join(UPLOADS_DIR, file.storedFilename);
        if (fs.existsSync(filepath)) fs.unlinkSync(filepath);
    }

    db.prepare('DELETE FROM files WHERE id = ?').run(req.params.fileId);
    res.json({ success: true });
});

// ============ FAVORITES ROUTES ============
app.get('/api/users/:userId/favorites', (req, res) => {
    const favorites = db.prepare('SELECT spaceId FROM user_favorites WHERE userId = ?').all(req.params.userId);
    res.json(favorites.map(f => f.spaceId));
});

app.post('/api/users/:userId/favorites/:spaceId', (req, res) => {
    try {
        db.prepare(`
            INSERT INTO user_favorites (id, userId, spaceId, createdAt)
            VALUES (?, ?, ?, ?)
        `).run(uuidv4(), req.params.userId, req.params.spaceId, new Date().toISOString());
        res.json({ success: true });
    } catch {
        res.json({ success: true }); // Already exists
    }
});

app.delete('/api/users/:userId/favorites/:spaceId', (req, res) => {
    db.prepare('DELETE FROM user_favorites WHERE userId = ? AND spaceId = ?').run(req.params.userId, req.params.spaceId);
    res.json({ success: true });
});

app.post('/api/users/:userId/favorites/:spaceId/toggle', (req, res) => {
    const existing = db.prepare('SELECT id FROM user_favorites WHERE userId = ? AND spaceId = ?').get(req.params.userId, req.params.spaceId);
    if (existing) {
        db.prepare('DELETE FROM user_favorites WHERE id = ?').run(existing.id);
        res.json({ isFavorite: false });
    } else {
        db.prepare(`INSERT INTO user_favorites (id, userId, spaceId, createdAt) VALUES (?, ?, ?, ?)`).run(uuidv4(), req.params.userId, req.params.spaceId, new Date().toISOString());
        res.json({ isFavorite: true });
    }
});

// ============ START SERVER ============
app.listen(PORT, () => {
    console.log(`🚀 Server running on http://localhost:${PORT}`);
    console.log(`📦 Using SQLite database: collabspace.db`);
});
