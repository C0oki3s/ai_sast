SELECT unit_key, execution_payload
FROM checkpoint_units
WHERE stage = ? AND status = 'failed_retryable' AND unit_key <> ?
