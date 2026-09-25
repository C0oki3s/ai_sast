BEGIN;

CREATE TABLE IF NOT EXISTS code_scanning_investigations (
  investigation_id VARCHAR(64) PRIMARY KEY,
  tenant_id VARCHAR(64) NOT NULL,
  scan_id VARCHAR(64) NOT NULL REFERENCES code_scanning_scan_runs(scan_id) ON DELETE CASCADE,
  codebase_id VARCHAR(64) NOT NULL REFERENCES code_scanning_codebases(codebase_id) ON DELETE CASCADE,
  snapshot_id VARCHAR(64) NOT NULL REFERENCES code_scanning_snapshots(snapshot_id) ON DELETE RESTRICT,
  stable_key VARCHAR(512) NOT NULL,
  evidence_hash VARCHAR(64) NOT NULL,
  investigation_data JSONB NOT NULL,
  state VARCHAR(32) NOT NULL DEFAULT 'planned',
  checkpoint_ref VARCHAR(512),
  revision INTEGER NOT NULL DEFAULT 1,
  attempt_count INTEGER NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT uq_code_scanning_investigation_evidence UNIQUE (scan_id, stable_key, evidence_hash),
  CONSTRAINT ck_code_scanning_investigation_state CHECK (
    state IN ('planned', 'running', 'candidate', 'no_candidate', 'unresolved', 'failed', 'skipped')
  ),
  CONSTRAINT ck_code_scanning_investigation_counters CHECK (revision > 0 AND attempt_count >= 0)
);

CREATE INDEX IF NOT EXISTS ix_code_scanning_investigation_queue
  ON code_scanning_investigations(tenant_id, scan_id, state, created_at);
CREATE INDEX IF NOT EXISTS ix_code_scanning_investigation_snapshot
  ON code_scanning_investigations(codebase_id, snapshot_id, stable_key);

INSERT INTO code_scanning_schema_migrations(version, checksum)
VALUES ('0006_investigations', 'managed-by-release-checksum')
ON CONFLICT (version) DO NOTHING;

COMMIT;
