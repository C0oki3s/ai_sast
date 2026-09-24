SELECT stage, last_error_type, execution_payload
FROM checkpoint_units
WHERE status IN ('running', 'failed_retryable', 'failed_final')
ORDER BY updated_at DESC, rowid DESC
LIMIT 1
