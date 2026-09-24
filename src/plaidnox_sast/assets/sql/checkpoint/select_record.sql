SELECT status, payload, context_payload, context_hash, execution_payload, last_error_type
FROM checkpoint_units
WHERE stage = ? AND unit_key = ?
