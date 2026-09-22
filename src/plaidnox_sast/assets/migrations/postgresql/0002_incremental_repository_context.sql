BEGIN;

CREATE TABLE IF NOT EXISTS code_scanning_repository_contexts (
  snapshot_id VARCHAR(64) PRIMARY KEY REFERENCES code_scanning_snapshots(snapshot_id) ON DELETE CASCADE,
  tenant_id VARCHAR(64) NOT NULL,
  codebase_id VARCHAR(64) NOT NULL REFERENCES code_scanning_codebases(codebase_id) ON DELETE CASCADE,
  context_hash VARCHAR(64) NOT NULL,
  context_data JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS ix_code_scanning_repository_contexts_tenant_id
  ON code_scanning_repository_contexts(tenant_id);

CREATE INDEX IF NOT EXISTS ix_code_scanning_repository_context
  ON code_scanning_repository_contexts(tenant_id, codebase_id, created_at);

INSERT INTO code_scanning_schema_migrations(version, checksum)
VALUES ('0002_incremental_repository_context', 'managed-by-release-checksum')
ON CONFLICT (version) DO NOTHING;

COMMIT;
