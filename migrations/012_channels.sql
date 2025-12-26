-- Channels table for Discord-like chat channels
CREATE TABLE IF NOT EXISTS channels (
    id TEXT PRIMARY KEY,
    spaceId TEXT NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    createdBy TEXT NOT NULL,
    createdAt TEXT NOT NULL,
    FOREIGN KEY (spaceId) REFERENCES spaces(id) ON DELETE CASCADE,
    FOREIGN KEY (createdBy) REFERENCES users(id)
);

-- Add channelId to messages table
ALTER TABLE messages ADD COLUMN channelId TEXT REFERENCES channels(id) ON DELETE CASCADE;
