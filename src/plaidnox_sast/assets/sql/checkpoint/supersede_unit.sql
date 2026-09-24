UPDATE checkpoint_units
SET status = 'superseded', updated_at = CURRENT_TIMESTAMP
WHERE stage = ? AND unit_key = ? AND status = 'failed_retryable'
