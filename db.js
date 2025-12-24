/**
 * Turso/LibSQL Database Module
 * Initializes cloud database and provides helper functions
 */

require('dotenv').config();
const { createClient } = require('@libsql/client');

// Initialize Turso client
const db = createClient({
    url: process.env.TURSO_DATABASE_URL,
    authToken: process.env.TURSO_AUTH_TOKEN
});

// Schema for table creation
const schema = `
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
`;

// Initialize database (run once on startup)
async function initDatabase() {
    try {
        // Execute each CREATE TABLE statement separately
        const statements = schema.split(';').filter(s => s.trim());
        for (const stmt of statements) {
            if (stmt.trim()) {
                await db.execute(stmt + ';');
            }
        }
        console.log('✅ Database initialized: Turso cloud database');
    } catch (error) {
        console.error('❌ Database initialization error:', error);
        throw error;
    }
}

// Helper functions to simplify query syntax
const query = {
    // Get a single row
    get: async (sql, params = []) => {
        const result = await db.execute({ sql, args: params });
        return result.rows[0] || null;
    },

    // Get all rows
    all: async (sql, params = []) => {
        const result = await db.execute({ sql, args: params });
        return result.rows;
    },

    // Execute a statement (INSERT, UPDATE, DELETE)
    run: async (sql, params = []) => {
        const result = await db.execute({ sql, args: params });
        return { changes: result.rowsAffected, lastInsertRowid: result.lastInsertRowid };
    },

    // Execute raw SQL
    exec: async (sql) => {
        return await db.execute(sql);
    }
};

module.exports = { db, query, initDatabase };
