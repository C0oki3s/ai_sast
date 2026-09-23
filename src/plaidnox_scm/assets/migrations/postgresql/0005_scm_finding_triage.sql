CREATE TABLE IF NOT EXISTS scm_finding_triage (
    tenant_id VARCHAR(64) NOT NULL,
    finding_id VARCHAR(64) NOT NULL,
    state VARCHAR(32) NOT NULL DEFAULT 'open',
    actor VARCHAR(255),
    reason TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, finding_id)
);

CREATE TABLE IF NOT EXISTS scm_finding_triage_events (
    id BIGSERIAL PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL,
    finding_id VARCHAR(64) NOT NULL,
    review_id VARCHAR(64) NOT NULL,
    command VARCHAR(32) NOT NULL,
    previous_state VARCHAR(32) NOT NULL,
    new_state VARCHAR(32) NOT NULL,
    actor VARCHAR(255) NOT NULL,
    reason TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS ix_scm_finding_triage_events_finding
    ON scm_finding_triage_events (tenant_id, finding_id, created_at);
