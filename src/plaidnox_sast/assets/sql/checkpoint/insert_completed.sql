INSERT INTO checkpoint_units(stage, unit_key, status, payload, updated_at)
VALUES (?, ?, 'completed', ?, CURRENT_TIMESTAMP)
