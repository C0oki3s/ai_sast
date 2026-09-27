INSERT INTO threat_statements(
  threat_statement_id, repository, category, statement, provenance, source_reference, version, status
)
VALUES (?, ?, ?, ?, ?, ?, 1, 'active')
ON CONFLICT(threat_statement_id) DO UPDATE SET
  version = threat_statements.version + CASE
    WHEN threat_statements.statement != excluded.statement
      OR threat_statements.provenance != excluded.provenance
      THEN 1 ELSE 0 END,
  statement = excluded.statement,
  provenance = excluded.provenance,
  status = 'active';
