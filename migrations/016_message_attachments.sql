-- Migration: Message attachments
-- Links messages to files stored in space files

CREATE TABLE IF NOT EXISTS message_attachments (
    id TEXT PRIMARY KEY,
    messageId TEXT NOT NULL,
    fileId TEXT NOT NULL,
    createdAt TEXT NOT NULL,
    FOREIGN KEY (messageId) REFERENCES messages(id) ON DELETE CASCADE,
    FOREIGN KEY (fileId) REFERENCES files(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_message_attachments_messageId ON message_attachments(messageId);
CREATE INDEX IF NOT EXISTS idx_message_attachments_fileId ON message_attachments(fileId);
