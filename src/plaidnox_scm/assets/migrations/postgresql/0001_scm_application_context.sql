CREATE TABLE IF NOT EXISTS scm_application_contexts (
    tenant_id VARCHAR(64) NOT NULL,
    codebase_id VARCHAR(64) NOT NULL,
    baseline_revision VARCHAR(64) NOT NULL,
    source_tree_hash VARCHAR(64) NOT NULL,
    builder_version VARCHAR(64) NOT NULL,
    application_type VARCHAR(128) NOT NULL DEFAULT '',
    entry_points JSONB NOT NULL DEFAULT '[]'::jsonb,
    components JSONB NOT NULL DEFAULT '[]'::jsonb,
    security_controls JSONB NOT NULL DEFAULT '[]'::jsonb,
    routes JSONB NOT NULL DEFAULT '[]'::jsonb,
    sensitive_effects JSONB NOT NULL DEFAULT '[]'::jsonb,
    environment_metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    identity_provider VARCHAR(128),
    prior_finding_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
    confidence DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    context_version VARCHAR(64) NOT NULL,
    computed_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, codebase_id)
);

CREATE INDEX IF NOT EXISTS ix_scm_application_contexts_tenant_id
    ON scm_application_contexts (tenant_id);
