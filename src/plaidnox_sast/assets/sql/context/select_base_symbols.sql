SELECT symbol_id, path, name, line, content_hash
FROM context_symbols
WHERE context_id = ?;
