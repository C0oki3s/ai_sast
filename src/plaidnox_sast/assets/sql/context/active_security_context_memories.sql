SELECT *
FROM security_memories
WHERE repository = ? AND status = 'active'
ORDER BY category, memory_id
LIMIT ?;
