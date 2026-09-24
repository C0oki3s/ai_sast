INSERT INTO knowledge_usage(
  usage_id, repository, scan_id, task_id, query, knowledge_id,
  decision, decision_confidence, reason
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(usage_id) DO UPDATE SET
  query = excluded.query,
  knowledge_id = excluded.knowledge_id,
  decision = excluded.decision,
  decision_confidence = excluded.decision_confidence,
  reason = excluded.reason;
