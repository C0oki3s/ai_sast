INSERT INTO knowledge_usage(
  usage_id, repository, scan_id, task_id, query, knowledge_id,
  decision, decision_confidence, reason
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
