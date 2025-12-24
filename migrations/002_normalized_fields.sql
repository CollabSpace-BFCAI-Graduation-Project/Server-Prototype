-- Add normalized fields for email and username
ALTER TABLE users ADD COLUMN emailNormalized TEXT;
ALTER TABLE users ADD COLUMN usernameNormalized TEXT;

-- Create indexes for faster lookups on normalized fields
CREATE INDEX IF NOT EXISTS idx_users_email_normalized ON users(emailNormalized);
CREATE INDEX IF NOT EXISTS idx_users_username_normalized ON users(usernameNormalized);
