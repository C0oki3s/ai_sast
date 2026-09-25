SELECT symbol_id, summary_state, content_hash, summary_json
FROM overlay_symbol_summaries
WHERE overlay_id = ?
  AND summary_state = 'active'
ORDER BY symbol_id;
