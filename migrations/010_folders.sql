-- Migration: Add folders table and folderId to files
-- Enables hierarchical folder structure for file organization within spaces

-- Folders table
CREATE TABLE IF NOT EXISTS folders (
    id TEXT PRIMARY KEY,
    spaceId TEXT NOT NULL,
    name TEXT NOT NULL,
    parentId TEXT DEFAULT NULL,
    createdBy TEXT NOT NULL,
    createdAt TEXT NOT NULL,
    FOREIGN KEY (spaceId) REFERENCES spaces(id) ON DELETE CASCADE,
    FOREIGN KEY (parentId) REFERENCES folders(id) ON DELETE CASCADE,
    FOREIGN KEY (createdBy) REFERENCES users(id)
);

-- Add folderId to files table (NULL = root level)
ALTER TABLE files ADD COLUMN folderId TEXT DEFAULT NULL REFERENCES folders(id) ON DELETE SET NULL;

-- Index for efficient folder queries
CREATE INDEX IF NOT EXISTS idx_folders_spaceId ON folders(spaceId);
CREATE INDEX IF NOT EXISTS idx_folders_parentId ON folders(parentId);
CREATE INDEX IF NOT EXISTS idx_files_folderId ON files(folderId);
