UPDATE checkpoint_units
SET status = 'failed_retryable',
    last_error_type = CASE WHEN last_error_type = '' THEN 'abandoned' ELSE last_error_type END,
    updated_at = CURRENT_TIMESTAMP
WHERE status IN ('running', 'pending')
