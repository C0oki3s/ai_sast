BEGIN;

CREATE TABLE IF NOT EXISTS code_scanning_surface_plans (
  scan_id VARCHAR(64) PRIMARY KEY
    REFERENCES code_scanning_scan_runs(scan_id) ON DELETE CASCADE,
  tenant_id VARCHAR(64) NOT NULL,
  snapshot_id VARCHAR(64) NOT NULL
    REFERENCES code_scanning_snapshots(snapshot_id) ON DELETE RESTRICT,
  state VARCHAR(32) NOT NULL DEFAULT 'planning',
  revision INTEGER NOT NULL DEFAULT 1,
  planning_data JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT ck_code_scanning_surface_plan_state_revision
    CHECK (revision > 0 AND state IN ('planning', 'complete'))
);

CREATE INDEX IF NOT EXISTS ix_code_scanning_surface_plan_tenant_snapshot
  ON code_scanning_surface_plans(tenant_id, snapshot_id);

INSERT INTO code_scanning_schema_migrations(version, checksum)
VALUES ('0008_graph_surface_planning', 'managed-by-release-checksum')
ON CONFLICT (version) DO NOTHING;

COMMIT;
