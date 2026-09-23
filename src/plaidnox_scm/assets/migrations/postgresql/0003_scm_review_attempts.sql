CREATE TABLE IF NOT EXISTS scm_review_attempts (
    review_id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL,
    codebase_id VARCHAR(64) NOT NULL,
    provider VARCHAR(32) NOT NULL,
    repository_id BIGINT NOT NULL,
    review_number INTEGER NOT NULL,
    base_sha VARCHAR(64) NOT NULL,
    head_sha VARCHAR(64) NOT NULL,
    delivery_id VARCHAR(255) NOT NULL,
    state VARCHAR(32) NOT NULL DEFAULT 'running',
    lease_owner VARCHAR(128),
    lease_expires_at TIMESTAMPTZ,
    attempt_count INTEGER NOT NULL DEFAULT 0,
    outcome VARCHAR(64),
    action VARCHAR(64),
    summary TEXT,
    incomplete_reason TEXT,
    counters JSONB,
    findings JSONB NOT NULL DEFAULT '[]'::jsonb,
    error_type VARCHAR(128),
    error_message TEXT,
    started_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS ix_scm_review_attempt_lease
    ON scm_review_attempts (state, lease_expires_at);

CREATE INDEX IF NOT EXISTS ix_scm_review_attempt_codebase
    ON scm_review_attempts (tenant_id, codebase_id, created_at);
