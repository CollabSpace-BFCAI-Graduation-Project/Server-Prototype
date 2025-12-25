-- Space Bans table
CREATE TABLE IF NOT EXISTS space_bans (
    id TEXT PRIMARY KEY,
    spaceId TEXT NOT NULL,
    userId TEXT NOT NULL,
    bannedBy TEXT NOT NULL,
    reason TEXT,
    createdAt TEXT NOT NULL,
    FOREIGN KEY (spaceId) REFERENCES spaces(id) ON DELETE CASCADE,
    FOREIGN KEY (userId) REFERENCES users(id),
    FOREIGN KEY (bannedBy) REFERENCES users(id),
    UNIQUE(spaceId, userId)
);
