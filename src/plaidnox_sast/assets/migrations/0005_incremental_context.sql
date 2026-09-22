PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS context_files (
  context_id TEXT NOT NULL,
  path TEXT NOT NULL,
  content_hash TEXT NOT NULL,
  PRIMARY KEY(context_id, path),
  FOREIGN KEY(context_id) REFERENCES context_bases(context_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS repository_context_documents (
  context_id TEXT PRIMARY KEY,
  repository TEXT NOT NULL,
  context_json TEXT NOT NULL,
  context_hash TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(context_id) REFERENCES context_bases(context_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_context_files_hash
  ON context_files(context_id, content_hash);

CREATE INDEX IF NOT EXISTS idx_repository_context_documents_repository
  ON repository_context_documents(repository, created_at);
