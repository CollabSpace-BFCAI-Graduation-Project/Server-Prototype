-- Migration: Add soft delete columns to messages table
-- This allows marking messages as deleted while preserving the record for auditing

ALTER TABLE messages ADD COLUMN deletedAt TEXT DEFAULT NULL;
ALTER TABLE messages ADD COLUMN deletedBy TEXT DEFAULT NULL;
ALTER TABLE messages ADD COLUMN deletedByRole TEXT DEFAULT NULL;

-- deletedAt: ISO timestamp of when the message was deleted
-- deletedBy: userId of the person who deleted the message
-- deletedByRole: 'author', 'Admin', or 'Owner' - indicates who deleted it
