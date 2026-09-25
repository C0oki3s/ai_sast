BEGIN;

CREATE INDEX IF NOT EXISTS ix_code_scanning_investigation_codebase_stable
  ON code_scanning_investigations(tenant_id, codebase_id, stable_key, created_at);

INSERT INTO code_scanning_schema_migrations(version, checksum)
VALUES ('0009_investigation_reuse_index', 'managed-by-release-checksum')
ON CONFLICT (version) DO NOTHING;

COMMIT;
