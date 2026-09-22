SELECT path, content_hash
FROM context_files
WHERE context_id = ?
ORDER BY path;
