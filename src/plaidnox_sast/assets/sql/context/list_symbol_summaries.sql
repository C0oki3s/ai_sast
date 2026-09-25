SELECT symbol_id, content_hash, summary_json
FROM context_symbol_summaries
WHERE context_id = ?
ORDER BY symbol_id;
