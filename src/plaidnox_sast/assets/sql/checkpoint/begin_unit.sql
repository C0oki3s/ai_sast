INSERT INTO checkpoint_units(
    stage, unit_key, status, payload, context_payload,
    context_hash, execution_payload, last_error_type, attempt_count, started_at, updated_at
) VALUES (?, ?, 'running', '{}', ?, ?, ?, '', 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
ON CONFLICT(stage, unit_key) DO UPDATE SET
    status = 'running',
    context_payload = excluded.context_payload,
    context_hash = excluded.context_hash,
    execution_payload = excluded.execution_payload,
    last_error_type = '',
    attempt_count = checkpoint_units.attempt_count + 1,
    started_at = CURRENT_TIMESTAMP,
    updated_at = CURRENT_TIMESTAMP
WHERE checkpoint_units.status <> 'completed'
