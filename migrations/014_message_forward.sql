-- Add forward support to messages
-- Stores the original channel name for display when forwarding
ALTER TABLE messages ADD COLUMN forwardedFromChannel TEXT;
-- Stores the original message ID for reference
ALTER TABLE messages ADD COLUMN forwardedFromMessageId TEXT;
