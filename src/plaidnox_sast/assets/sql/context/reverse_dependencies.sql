SELECT source_symbol
FROM context_edges
WHERE context_id = ? AND target_symbol IN ({{symbol_placeholders}});
