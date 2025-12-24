-- Account lockout fields
ALTER TABLE users ADD COLUMN failedLoginAttempts INTEGER DEFAULT 0;
ALTER TABLE users ADD COLUMN lockedUntil TEXT;
ALTER TABLE users ADD COLUMN lastFailedLoginAt TEXT;
