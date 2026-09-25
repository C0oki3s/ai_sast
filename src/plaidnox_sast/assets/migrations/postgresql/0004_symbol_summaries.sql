BEGIN;

CREATE TABLE IF NOT EXISTS code_scanning_symbol_summaries (
  summary_record_id VARCHAR(64) PRIMARY KEY,
  snapshot_id VARCHAR(64) NOT NULL REFERENCES code_scanning_snapshots(snapshot_id) ON DELETE CASCADE,
  symbol_id VARCHAR(2048) NOT NULL,
  content_hash VARCHAR(64) NOT NULL,
  summary_data JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT uq_code_scanning_symbol_summary UNIQUE (snapshot_id, symbol_id)
);

CREATE INDEX IF NOT EXISTS ix_code_scanning_symbol_summary_snapshot
  ON code_scanning_symbol_summaries(snapshot_id, content_hash);

INSERT INTO code_scanning_schema_migrations(version, checksum)
VALUES ('0004_symbol_summaries', 'managed-by-release-checksum')
ON CONFLICT (version) DO NOTHING;

COMMIT;
