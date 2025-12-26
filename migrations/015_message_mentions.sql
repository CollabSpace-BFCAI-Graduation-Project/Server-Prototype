-- Create a separate table for message mentions to allow robust querying
CREATE TABLE IF NOT EXISTS message_mentions (
    id TEXT PRIMARY KEY,
    messageId TEXT NOT NULL,
    userId TEXT NOT NULL,
    createdAt TEXT NOT NULL,
    FOREIGN KEY (messageId) REFERENCES messages(id) ON DELETE CASCADE,
    FOREIGN KEY (userId) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE(messageId, userId)
);

-- Index for faster lookups of "my mentions"
CREATE INDEX IF NOT EXISTS idx_message_mentions_userId ON message_mentions(userId);
