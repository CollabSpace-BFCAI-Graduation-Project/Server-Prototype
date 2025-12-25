-- Add visibility setting to spaces
ALTER TABLE spaces ADD COLUMN visibility TEXT DEFAULT 'private';
-- visibility: 'public' | 'private'
-- public = visible to everyone, private = visible only to members
