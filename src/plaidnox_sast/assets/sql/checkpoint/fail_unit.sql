UPDATE checkpoint_units
SET status = 'pending', last_error_type = ?, updated_at = CURRENT_TIMESTAMP
WHERE stage = ? AND unit_key = ? AND status <> 'completed'
