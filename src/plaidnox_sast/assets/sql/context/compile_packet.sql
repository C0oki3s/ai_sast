SELECT symbol_id, path, name, content
FROM overlay_symbols
WHERE overlay_id = ? AND symbol_id IN ({{symbol_placeholders}})
UNION ALL
SELECT base.symbol_id, base.path, base.name, base.content
FROM context_symbols base
WHERE base.context_id = ? AND base.symbol_id IN ({{symbol_placeholders}})
  AND NOT EXISTS (
    SELECT 1
    FROM overlay_symbols overlay
    WHERE overlay.overlay_id = ? AND overlay.symbol_id = base.symbol_id
  );
