/**
 * Data Migration Script
 * Imports existing JSON data into SQLite database
 * Run once: node migrate-data.js
 */

const fs = require('fs');
const path = require('path');
const db = require('./db');

const DATA_DIR = path.join(__dirname, 'data');

// Disable FK checks during migration (some JSON data may have orphan references)
db.pragma('foreign_keys = OFF');

// Helper to read JSON file
const readJson = (filename) => {
    const filepath = path.join(DATA_DIR, filename);
    if (!fs.existsSync(filepath)) return [];
    return JSON.parse(fs.readFileSync(filepath, 'utf8'));
};

console.log('🚀 Starting data migration...\n');

// ============ USERS ============
console.log('📦 Migrating users...');
const users = readJson('users.json');
const insertUser = db.prepare(`
    INSERT OR REPLACE INTO users (id, name, username, email, password, avatarColor, avatarImage, bio, createdAt)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
`);
users.forEach(u => {
    insertUser.run(u.id, u.name, u.username, u.email, u.password, u.avatarColor || '#9ca3af', u.avatarImage, u.bio || '', u.createdAt);
});
console.log(`   ✅ ${users.length} users migrated`);

// ============ SPACES ============
console.log('📦 Migrating spaces...');
const spaces = readJson('spaces.json');
const insertSpace = db.prepare(`
    INSERT OR REPLACE INTO spaces (id, name, thumbnailGradient, thumbnailImage, category, description, ownerId, createdAt)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
`);
spaces.forEach(s => {
    // Old 'thumbnail' field becomes 'thumbnailGradient' (it was CSS gradient)
    insertSpace.run(s.id, s.name, s.thumbnail, null, s.category, s.description, s.ownerId, s.createdAt);
});
console.log(`   ✅ ${spaces.length} spaces migrated`);

// ============ SPACE MEMBERS ============
console.log('📦 Migrating space members...');
const members = readJson('space_members.json');
const insertMember = db.prepare(`
    INSERT OR REPLACE INTO space_members (id, spaceId, userId, role, joinedAt)
    VALUES (?, ?, ?, ?, ?)
`);
members.forEach(m => {
    insertMember.run(m.id, m.spaceId, m.userId, m.role, m.joinedAt);
});
console.log(`   ✅ ${members.length} members migrated`);

// ============ SPACE INVITES ============
console.log('📦 Migrating space invites...');
const invites = readJson('space_invites.json');
const insertInvite = db.prepare(`
    INSERT OR REPLACE INTO space_invites (id, spaceId, userId, inviterId, status, createdAt, respondedAt)
    VALUES (?, ?, ?, ?, ?, ?, ?)
`);
invites.forEach(i => {
    insertInvite.run(i.id, i.spaceId, i.userId, i.inviterId, i.status, i.createdAt, i.respondedAt);
});
console.log(`   ✅ ${invites.length} invites migrated`);

// ============ MESSAGES ============
console.log('📦 Migrating messages...');
const messages = readJson('messages.json');
const insertMessage = db.prepare(`
    INSERT OR REPLACE INTO messages (id, spaceId, senderId, text, type, mentions, createdAt)
    VALUES (?, ?, ?, ?, ?, ?, ?)
`);
messages.forEach(m => {
    const mentions = m.mentions ? JSON.stringify(m.mentions) : null;
    insertMessage.run(m.id, m.spaceId, m.senderId, m.text, m.type || 'user', mentions, m.createdAt);
});
console.log(`   ✅ ${messages.length} messages migrated`);

// ============ NOTIFICATIONS ============
console.log('📦 Migrating notifications...');
const notifications = readJson('notifications.json');
const insertNotification = db.prepare(`
    INSERT OR REPLACE INTO notifications (id, userId, type, actorId, targetType, targetId, message, read, createdAt)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
`);
notifications.forEach(n => {
    // Map old structure to new
    // Old: author, text, target, spaceId, inviteId
    // New: actorId (lookup by author name), targetType, targetId, message

    // Try to find actor by name
    const actor = users.find(u => u.name === n.author);
    const actorId = actor?.id || null;

    // Determine target type and ID
    let targetType = null;
    let targetId = null;
    if (n.spaceId) {
        targetType = 'space';
        targetId = n.spaceId;
    } else if (n.inviteId) {
        targetType = 'invite';
        targetId = n.inviteId;
    }

    // Compose message from old fields
    const message = n.text ? `${n.author || ''} ${n.text} ${n.target || ''}`.trim() : null;

    insertNotification.run(n.id, n.userId, n.type, actorId, targetType, targetId, message, n.read ? 1 : 0, n.createdAt);
});
console.log(`   ✅ ${notifications.length} notifications migrated`);

// ============ FILES ============
console.log('📦 Migrating files...');
const files = readJson('files.json');
const insertFile = db.prepare(`
    INSERT OR REPLACE INTO files (id, spaceId, name, storedFilename, type, mimeType, size, uploadedBy, downloadUrl, createdAt)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`);
files.forEach(f => {
    insertFile.run(f.id, f.spaceId, f.name, f.storedFilename, f.type, f.mimeType, f.size, f.uploadedBy, f.downloadUrl, f.createdAt);
});
console.log(`   ✅ ${files.length} files migrated`);

// ============ USER FAVORITES ============
console.log('📦 Migrating user favorites...');
const favorites = readJson('user_favorites.json');
const insertFavorite = db.prepare(`
    INSERT OR REPLACE INTO user_favorites (id, userId, spaceId, createdAt)
    VALUES (?, ?, ?, ?)
`);
favorites.forEach(f => {
    insertFavorite.run(f.id, f.userId, f.spaceId, f.createdAt);
});
console.log(`   ✅ ${favorites.length} favorites migrated`);

console.log('\n🎉 Migration complete!');
console.log('   Database file: collabspace.db');
console.log('   Original JSON files preserved in data/ folder');
