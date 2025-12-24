-- OAuth providers linked accounts
CREATE TABLE IF NOT EXISTS oauth_providers (
    id TEXT PRIMARY KEY,
    userId TEXT NOT NULL,
    provider TEXT NOT NULL,
    providerUserId TEXT NOT NULL,
    email TEXT,
    createdAt TEXT NOT NULL,
    UNIQUE(provider, providerUserId),
    FOREIGN KEY (userId) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_oauth_provider_user ON oauth_providers(provider, providerUserId);
