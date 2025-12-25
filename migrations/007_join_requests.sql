-- Create join requests table
CREATE TABLE IF NOT EXISTS join_requests (
    id TEXT PRIMARY KEY,
    spaceId TEXT NOT NULL,
    userId TEXT NOT NULL,
    status TEXT DEFAULT 'pending', -- pending, approved, rejected
    createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (spaceId) REFERENCES spaces(id) ON DELETE CASCADE,
    FOREIGN KEY (userId) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE(spaceId, userId) -- Prevent duplicate requests
);
