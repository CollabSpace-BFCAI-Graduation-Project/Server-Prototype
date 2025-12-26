-- Invite Links for shareable space invites (Discord-style)
CREATE TABLE IF NOT EXISTS invite_links (
    id TEXT PRIMARY KEY,
    code TEXT UNIQUE NOT NULL,
    spaceId TEXT NOT NULL,
    creatorId TEXT NOT NULL,
    expiresAt TEXT,
    maxUses INTEGER,
    uses INTEGER DEFAULT 0,
    createdAt TEXT NOT NULL,
    FOREIGN KEY (spaceId) REFERENCES spaces(id) ON DELETE CASCADE,
    FOREIGN KEY (creatorId) REFERENCES users(id)
);

-- Index for fast code lookups
CREATE INDEX IF NOT EXISTS idx_invite_links_code ON invite_links(code);
CREATE INDEX IF NOT EXISTS idx_invite_links_spaceId ON invite_links(spaceId);
