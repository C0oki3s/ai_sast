BEGIN;

CREATE TABLE IF NOT EXISTS code_scanning_overlay_symbol_summaries (
  summary_record_id VARCHAR(64) PRIMARY KEY,
  snapshot_id VARCHAR(64) NOT NULL REFERENCES code_scanning_snapshots(snapshot_id) ON DELETE CASCADE,
  symbol_id VARCHAR(2048) NOT NULL,
  summary_state VARCHAR(16) NOT NULL,
  content_hash VARCHAR(64),
  summary_data JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT uq_code_scanning_overlay_symbol_summary UNIQUE (snapshot_id, symbol_id),
  CONSTRAINT ck_code_scanning_overlay_symbol_summary_state CHECK (
    (summary_state = 'active' AND content_hash IS NOT NULL AND summary_data IS NOT NULL) OR
    (summary_state = 'deleted' AND content_hash IS NULL AND summary_data IS NULL)
  )
);

CREATE INDEX IF NOT EXISTS ix_code_scanning_overlay_symbol_summary_snapshot
  ON code_scanning_overlay_symbol_summaries(snapshot_id, summary_state);

INSERT INTO code_scanning_schema_migrations(version, checksum)
VALUES ('0005_sparse_overlay_summaries', 'managed-by-release-checksum')
ON CONFLICT (version) DO NOTHING;

COMMIT;
