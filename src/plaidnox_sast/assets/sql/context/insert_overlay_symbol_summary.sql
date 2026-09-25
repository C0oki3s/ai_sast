INSERT INTO overlay_symbol_summaries(
  overlay_id, symbol_id, summary_state, content_hash, summary_json
)
VALUES (?, ?, 'active', ?, ?);
