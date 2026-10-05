CREATE TABLE IF NOT EXISTS scm_installation_tenants (
    provider VARCHAR(32) NOT NULL,
    installation_id BIGINT NOT NULL,
    tenant_id VARCHAR(64) NOT NULL,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (provider, installation_id)
);
CREATE INDEX IF NOT EXISTS ix_scm_installation_tenant
    ON scm_installation_tenants (tenant_id, provider);

CREATE TABLE IF NOT EXISTS scm_webhook_deliveries (
    delivery_id VARCHAR(255) PRIMARY KEY,
    provider VARCHAR(32) NOT NULL,
    installation_id BIGINT NOT NULL,
    repository_id BIGINT NOT NULL,
    event_name VARCHAR(64) NOT NULL,
    action VARCHAR(64),
    tenant_id VARCHAR(64) NOT NULL,
    state VARCHAR(24) NOT NULL DEFAULT 'accepted',
    received_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS scm_activity_events (
    event_id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL,
    codebase_id VARCHAR(64) NOT NULL,
    provider VARCHAR(32) NOT NULL,
    repository_id BIGINT NOT NULL,
    installation_id BIGINT NOT NULL,
    pull_number INTEGER,
    review_id VARCHAR(64),
    head_sha VARCHAR(64),
    event_type VARCHAR(40) NOT NULL,
    summary VARCHAR(255) NOT NULL,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    idempotency_key VARCHAR(255) NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS ix_scm_activity_tenant_time
    ON scm_activity_events (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS ix_scm_activity_tenant_codebase_time
    ON scm_activity_events (tenant_id, codebase_id, created_at DESC);
