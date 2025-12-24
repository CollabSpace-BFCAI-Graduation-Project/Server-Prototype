/**
 * SQLite Database Module
 * Initializes database and provides helper functions
 */

const Database = require('better-sqlite3');
const path = require('path');

// Initialize database
const dbPath = path.join(__dirname, 'collabspace.db');
const db = new Database(dbPath);

// Enable foreign keys
db.pragma('foreign_keys = ON');

// Create tables
db.exec(`
    -- Users
    CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        avatarColor TEXT DEFAULT '#9ca3af',
        avatarImage TEXT,
        bio TEXT DEFAULT '',
        createdAt TEXT NOT NULL
    );

    -- Spaces
    CREATE TABLE IF NOT EXISTS spaces (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        thumbnailGradient TEXT,
        thumbnailImage TEXT,
        category TEXT,
        description TEXT,
        ownerId TEXT NOT NULL,
        createdAt TEXT NOT NULL,
        FOREIGN KEY (ownerId) REFERENCES users(id)
    );

    -- Space Members
    CREATE TABLE IF NOT EXISTS space_members (
        id TEXT PRIMARY KEY,
        spaceId TEXT NOT NULL,
        userId TEXT NOT NULL,
        role TEXT DEFAULT 'Member',
        joinedAt TEXT NOT NULL,
        FOREIGN KEY (spaceId) REFERENCES spaces(id) ON DELETE CASCADE,
        FOREIGN KEY (userId) REFERENCES users(id),
        UNIQUE(spaceId, userId)
    );

    -- Space Invites
    CREATE TABLE IF NOT EXISTS space_invites (
        id TEXT PRIMARY KEY,
        spaceId TEXT NOT NULL,
        userId TEXT NOT NULL,
        inviterId TEXT NOT NULL,
        status TEXT DEFAULT 'pending',
        createdAt TEXT NOT NULL,
        respondedAt TEXT,
        FOREIGN KEY (spaceId) REFERENCES spaces(id) ON DELETE CASCADE,
        FOREIGN KEY (userId) REFERENCES users(id),
        FOREIGN KEY (inviterId) REFERENCES users(id)
    );

    -- Messages
    CREATE TABLE IF NOT EXISTS messages (
        id TEXT PRIMARY KEY,
        spaceId TEXT NOT NULL,
        senderId TEXT,
        text TEXT NOT NULL,
        type TEXT DEFAULT 'user',
        mentions TEXT,
        createdAt TEXT NOT NULL,
        FOREIGN KEY (spaceId) REFERENCES spaces(id) ON DELETE CASCADE
    );

    -- Notifications
    CREATE TABLE IF NOT EXISTS notifications (
        id TEXT PRIMARY KEY,
        userId TEXT NOT NULL,
        type TEXT NOT NULL,
        actorId TEXT,
        targetType TEXT,
        targetId TEXT,
        message TEXT,
        read INTEGER DEFAULT 0,
        createdAt TEXT NOT NULL,
        FOREIGN KEY (userId) REFERENCES users(id),
        FOREIGN KEY (actorId) REFERENCES users(id)
    );

    -- Files
    CREATE TABLE IF NOT EXISTS files (
        id TEXT PRIMARY KEY,
        spaceId TEXT NOT NULL,
        name TEXT NOT NULL,
        storedFilename TEXT,
        type TEXT,
        mimeType TEXT,
        size TEXT,
        uploadedBy TEXT,
        downloadUrl TEXT,
        createdAt TEXT NOT NULL,
        FOREIGN KEY (spaceId) REFERENCES spaces(id) ON DELETE CASCADE
    );

    -- User Favorites
    CREATE TABLE IF NOT EXISTS user_favorites (
        id TEXT PRIMARY KEY,
        userId TEXT NOT NULL,
        spaceId TEXT NOT NULL,
        createdAt TEXT NOT NULL,
        FOREIGN KEY (userId) REFERENCES users(id),
        FOREIGN KEY (spaceId) REFERENCES spaces(id) ON DELETE CASCADE,
        UNIQUE(userId, spaceId)
    );
`);

console.log('✅ Database initialized: collabspace.db');

module.exports = db;
