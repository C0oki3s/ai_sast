-- Per-scope finding lifecycle: one row per finding per pull request (scope
-- "pr:<number>") and on the default branch (scope "branch").
-- status: open | fixed | duplicate | closed | merged
CREATE TABLE IF NOT EXISTS scm_finding_occurrences (
    tenant_id VARCHAR(64) NOT NULL,
    codebase_id VARCHAR(64) NOT NULL,
    scope VARCHAR(32) NOT NULL,
    finding_id VARCHAR(64) NOT NULL,
    status VARCHAR(16) NOT NULL DEFAULT 'open',
    finding JSONB NOT NULL DEFAULT '{}'::jsonb,
    first_seen_review_id VARCHAR(64),
    last_seen_review_id VARCHAR(64),
    last_seen_head VARCHAR(64),
    fixed_review_id VARCHAR(64),
    fixed_head VARCHAR(64),
    fixed_reason TEXT,
    reopened_count INTEGER NOT NULL DEFAULT 0,
    last_run_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, codebase_id, scope, finding_id)
);
CREATE INDEX IF NOT EXISTS ix_scm_finding_occurrences_scope
    ON scm_finding_occurrences (tenant_id, codebase_id, scope, status);
ALTER TABLE scm_finding_occurrences ADD COLUMN IF NOT EXISTS last_run_at TIMESTAMPTZ;

-- Open/closed/merged per pull request. Review runs and merge/close events lock this
-- row, so a review that started before a PR closed cannot reopen its findings.
CREATE TABLE IF NOT EXISTS scm_pull_request_states (
    tenant_id VARCHAR(64) NOT NULL,
    codebase_id VARCHAR(64) NOT NULL,
    review_number INTEGER NOT NULL,
    state VARCHAR(16) NOT NULL DEFAULT 'open',
    changed_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, codebase_id, review_number)
);
