-- Add reply support to messages
ALTER TABLE messages ADD COLUMN replyToId TEXT REFERENCES messages(id) ON DELETE SET NULL;