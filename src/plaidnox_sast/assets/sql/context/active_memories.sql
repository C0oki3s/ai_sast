SELECT *
FROM security_memories
WHERE repository = ? AND status = 'active'
  AND (category = ? OR category = 'general')
ORDER BY version DESC;
