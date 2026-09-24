CREATE TABLE IF NOT EXISTS checkpoint_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS checkpoint_units (
    stage TEXT NOT NULL,
    unit_key TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'completed',
    payload TEXT NOT NULL DEFAULT '{}',
    context_payload TEXT NOT NULL DEFAULT '{}',
    context_hash TEXT NOT NULL DEFAULT '',
    execution_payload TEXT NOT NULL DEFAULT '{}',
    last_error_type TEXT NOT NULL DEFAULT '',
    attempt_count INTEGER NOT NULL DEFAULT 0,
    started_at TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (stage, unit_key)
);
