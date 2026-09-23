BEGIN;

CREATE TABLE IF NOT EXISTS code_scanning_tenant_controls (
  tenant_id VARCHAR(64) PRIMARY KEY,
  maximum_concurrent_jobs INTEGER NOT NULL,
  maximum_daily_jobs INTEGER NOT NULL,
  maximum_monthly_model_cost_usd DOUBLE PRECISION NOT NULL,
  completed_scan_retention_days INTEGER NOT NULL,
  failed_scan_retention_days INTEGER NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT ck_code_scanning_tenant_controls_nonnegative CHECK (
    maximum_concurrent_jobs > 0 AND maximum_daily_jobs > 0
    AND maximum_monthly_model_cost_usd >= 0
    AND completed_scan_retention_days > 0 AND failed_scan_retention_days > 0
  )
);

CREATE TABLE IF NOT EXISTS code_scanning_scan_jobs (
  job_id VARCHAR(64) PRIMARY KEY,
  tenant_id VARCHAR(64) NOT NULL,
  request_key VARCHAR(128) NOT NULL,
  codebase_external_key VARCHAR(512) NOT NULL,
  revision VARCHAR(128) NOT NULL,
  snapshot_uri TEXT NOT NULL,
  output_uri TEXT NOT NULL,
  job_data JSONB NOT NULL DEFAULT '{}'::jsonb,
  state VARCHAR(32) NOT NULL DEFAULT 'queued',
  priority INTEGER NOT NULL DEFAULT 100,
  attempt_count INTEGER NOT NULL DEFAULT 0,
  maximum_attempts INTEGER NOT NULL,
  lease_owner VARCHAR(128),
  lease_expires_at TIMESTAMPTZ,
  failure_code VARCHAR(128) NOT NULL DEFAULT '',
  result_summary JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT uq_code_scanning_scan_job_request UNIQUE (tenant_id, request_key),
  CONSTRAINT ck_code_scanning_scan_job_attempts CHECK (
    attempt_count >= 0 AND maximum_attempts > 0 AND priority >= 0
  )
);
CREATE INDEX IF NOT EXISTS ix_code_scanning_scan_job_lease
  ON code_scanning_scan_jobs(tenant_id, state, priority, lease_expires_at, created_at);

CREATE TABLE IF NOT EXISTS code_scanning_usage_events (
  usage_event_id VARCHAR(64) PRIMARY KEY,
  tenant_id VARCHAR(64) NOT NULL,
  scan_id VARCHAR(64) REFERENCES code_scanning_scan_runs(scan_id) ON DELETE SET NULL,
  model_alias VARCHAR(255) NOT NULL,
  input_tokens INTEGER NOT NULL DEFAULT 0,
  output_tokens INTEGER NOT NULL DEFAULT 0,
  cost_usd DOUBLE PRECISION NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT ck_code_scanning_usage_nonnegative CHECK (
    input_tokens >= 0 AND output_tokens >= 0 AND cost_usd >= 0
  )
);
CREATE INDEX IF NOT EXISTS ix_code_scanning_usage_tenant_time
  ON code_scanning_usage_events(tenant_id, created_at);

CREATE TABLE IF NOT EXISTS code_scanning_audit_events (
  audit_event_id VARCHAR(64) PRIMARY KEY,
  tenant_id VARCHAR(64) NOT NULL,
  event_type VARCHAR(128) NOT NULL,
  actor_type VARCHAR(64) NOT NULL,
  actor_id VARCHAR(255) NOT NULL,
  resource_type VARCHAR(64) NOT NULL,
  resource_id VARCHAR(255) NOT NULL,
  outcome VARCHAR(32) NOT NULL,
  details JSONB NOT NULL DEFAULT '{}'::jsonb,
  event_hash VARCHAR(64) NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS ix_code_scanning_audit_tenant_time
  ON code_scanning_audit_events(tenant_id, created_at);

CREATE TABLE IF NOT EXISTS code_scanning_artifacts (
  artifact_id VARCHAR(64) PRIMARY KEY,
  tenant_id VARCHAR(64) NOT NULL,
  scan_id VARCHAR(64) REFERENCES code_scanning_scan_runs(scan_id) ON DELETE CASCADE,
  artifact_kind VARCHAR(64) NOT NULL,
  storage_uri TEXT NOT NULL,
  content_hash VARCHAR(64) NOT NULL,
  encryption_key_ref TEXT NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  deleted_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT uq_code_scanning_artifact_uri UNIQUE (tenant_id, storage_uri)
);
CREATE INDEX IF NOT EXISTS ix_code_scanning_artifact_expiry
  ON code_scanning_artifacts(tenant_id, expires_at, deleted_at);

CREATE TABLE IF NOT EXISTS code_scanning_deletion_requests (
  deletion_request_id VARCHAR(64) PRIMARY KEY,
  tenant_id VARCHAR(64) NOT NULL,
  resource_type VARCHAR(64) NOT NULL,
  resource_id VARCHAR(255) NOT NULL,
  requested_by VARCHAR(255) NOT NULL,
  reason TEXT NOT NULL,
  state VARCHAR(32) NOT NULL DEFAULT 'pending',
  completed_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS ix_code_scanning_deletion_state
  ON code_scanning_deletion_requests(tenant_id, state, created_at);

INSERT INTO code_scanning_schema_migrations(version, checksum)
VALUES ('0003_production_controls', 'managed-by-release-checksum')
ON CONFLICT (version) DO NOTHING;

COMMIT;
