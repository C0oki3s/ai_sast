UPDATE checkpoint_units
SET status = 'completed', payload = ?, last_error_type = '', updated_at = CURRENT_TIMESTAMP
WHERE stage = ? AND unit_key = ?
