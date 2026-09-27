CREATE TABLE IF NOT EXISTS threat_statements (
  threat_statement_id TEXT PRIMARY KEY,
  repository TEXT NOT NULL,
  category TEXT NOT NULL,
  statement TEXT NOT NULL,
  provenance TEXT NOT NULL,
  source_reference TEXT NOT NULL DEFAULT '',
  version INTEGER NOT NULL DEFAULT 1,
  status TEXT NOT NULL DEFAULT 'active',
  CHECK(version > 0)
);

CREATE INDEX IF NOT EXISTS idx_threat_statements_repository_status
  ON threat_statements(repository, status, category);
