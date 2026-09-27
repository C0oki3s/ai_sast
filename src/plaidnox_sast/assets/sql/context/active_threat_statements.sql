SELECT threat_statement_id, repository, category, statement, provenance, source_reference, version
FROM threat_statements
WHERE repository = ? AND status = 'active'
ORDER BY category, threat_statement_id
LIMIT ?;
