INSERT INTO checkpoint_units(
    stage, unit_key, status, payload, context_payload,
    context_hash, execution_payload, last_error_type, updated_at
) VALUES (?, ?, 'pending', '{}', ?, ?, ?, '', CURRENT_TIMESTAMP)
ON CONFLICT(stage, unit_key) DO UPDATE SET
    status = 'pending',
    context_payload = excluded.context_payload,
    context_hash = excluded.context_hash,
    execution_payload = excluded.execution_payload,
    last_error_type = '',
    updated_at = CURRENT_TIMESTAMP
WHERE checkpoint_units.status <> 'completed'
