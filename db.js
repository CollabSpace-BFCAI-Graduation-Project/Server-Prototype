/**
 * Database Module
 * Supports both Local SQLite and Turso Cloud
 * Toggles via DB_PROVIDER env var ('local' or 'turso')
 */

require('dotenv').config();
const fs = require('fs');
const path = require('path');

const DB_PROVIDER = process.env.DB_PROVIDER || 'local';

console.log(`🔌 Database Provider: ${DB_PROVIDER.toUpperCase()}`);

let db;
let query;

// ==========================================
// TURSO CLOUD SETUP
// ==========================================
if (DB_PROVIDER === 'turso') {
    const { createClient } = require('@libsql/client');

    db = createClient({
        url: process.env.TURSO_DATABASE_URL,
        authToken: process.env.TURSO_AUTH_TOKEN
    });

    query = {
        get: async (sql, params = []) => {
            const result = await db.execute({ sql, args: params });
            return result.rows[0] || null;
        },
        all: async (sql, params = []) => {
            const result = await db.execute({ sql, args: params });
            return result.rows;
        },
        run: async (sql, params = []) => {
            const result = await db.execute({ sql, args: params });
            return { changes: result.rowsAffected, lastInsertRowid: result.lastInsertRowid };
        },
        exec: async (sql) => {
            return await db.execute(sql);
        }
    };

    // ==========================================
    // LOCAL SQLITE SETUP
    // ==========================================
} else {
    const Database = require('better-sqlite3');
    const dbPath = path.join(__dirname, 'collabspace.db');

    // Ensure directory exists
    const dbDir = path.dirname(dbPath);
    if (!fs.existsSync(dbDir)) {
        fs.mkdirSync(dbDir, { recursive: true });
    }

    db = new Database(dbPath);
    db.pragma('foreign_keys = ON');

    // unified async wrapper to match Turso interface
    query = {
        get: async (sql, params = []) => {
            return db.prepare(sql).get(params);
        },
        all: async (sql, params = []) => {
            return db.prepare(sql).all(params);
        },
        run: async (sql, params = []) => {
            const result = db.prepare(sql).run(params);
            return { changes: result.changes, lastInsertRowid: result.lastInsertRowid };
        },
        exec: async (sql) => {
            return db.exec(sql);
        }
    };
}

// ==========================================
// MIGRATION SYSTEM
// ==========================================
async function initDatabase() {
    try {
        const migrationsDir = path.join(__dirname, 'migrations');
        if (!fs.existsSync(migrationsDir)) return;

        // Create migrations table if not exists
        await query.exec(`
            CREATE TABLE IF NOT EXISTS _migrations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                applied_at TEXT NOT NULL
            );
        `);

        // Get list of migration files
        const files = fs.readdirSync(migrationsDir)
            .filter(f => f.endsWith('.sql'))
            .sort();

        // Get applied migrations
        const appliedRows = await query.all('SELECT name FROM _migrations');
        const applied = new Set(appliedRows.map(r => r.name));

        // Apply new migrations
        for (const file of files) {
            if (!applied.has(file)) {
                console.log(`📦 Applying migration: ${file}`);
                const sql = fs.readFileSync(path.join(migrationsDir, file), 'utf8');

                // Split by semi-colon to handle multiple statements if provider requires it
                // Turso/LibSQL execute() handles single statements better usually, but local exec() handles script.
                // For safety/compatibility, we can try unified approach if needed, but exec() usually takes scripts.
                // However, Turso's execute() is strictly one statement? No, execute() is one, executeMultiple() is available in some clients but here we used execute.
                // Safe bet: split statements.

                const statements = sql.split(';').filter(s => s.trim());
                for (const stmt of statements) {
                    if (stmt.trim()) {
                        await query.exec(stmt + ';');
                    }
                }

                await query.run('INSERT INTO _migrations (name, applied_at) VALUES (?, ?)', [file, new Date().toISOString()]);
            }
        }

    } catch (error) {
        console.error('❌ Database initialization error:', error);
        throw error;
    }
}

module.exports = { db, query, initDatabase, provider: DB_PROVIDER };
