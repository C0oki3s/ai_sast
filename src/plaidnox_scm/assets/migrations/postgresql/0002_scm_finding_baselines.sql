CREATE TABLE IF NOT EXISTS scm_finding_baselines (
    tenant_id VARCHAR(64) NOT NULL,
    codebase_id VARCHAR(64) NOT NULL,
    baseline_revision VARCHAR(64) NOT NULL,
    root_cause_fingerprint VARCHAR(64) NOT NULL,
    finding_fingerprint VARCHAR(64) NOT NULL,
    lifecycle_state VARCHAR(32) NOT NULL,
    root_cause_path TEXT NOT NULL,
    root_cause_symbol TEXT NOT NULL,
    vulnerability_class TEXT NOT NULL,
    title TEXT NOT NULL,
    severity VARCHAR(32) NOT NULL,
    confidence DOUBLE PRECISION NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, codebase_id, baseline_revision, root_cause_fingerprint)
);

CREATE INDEX IF NOT EXISTS ix_scm_finding_baselines_lookup
    ON scm_finding_baselines (tenant_id, codebase_id, baseline_revision, lifecycle_state);
