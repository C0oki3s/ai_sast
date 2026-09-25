PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS context_symbol_summaries (
  context_id TEXT NOT NULL,
  symbol_id TEXT NOT NULL,
  content_hash TEXT NOT NULL,
  summary_json TEXT NOT NULL,
  PRIMARY KEY(context_id, symbol_id),
  FOREIGN KEY(context_id) REFERENCES context_bases(context_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_context_symbol_summaries_hash
  ON context_symbol_summaries(context_id, content_hash);
