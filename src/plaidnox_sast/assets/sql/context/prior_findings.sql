SELECT DISTINCT fingerprint
FROM finding_dependencies
WHERE repository = ? AND symbol_id IN ({{symbol_placeholders}});
