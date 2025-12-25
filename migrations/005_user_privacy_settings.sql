-- Add privacy settings to users table
ALTER TABLE users ADD COLUMN showEmail INTEGER DEFAULT 0;
ALTER TABLE users ADD COLUMN profileVisibility TEXT DEFAULT 'public';
-- profileVisibility: 'public' | 'members' | 'private'
