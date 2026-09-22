INSERT INTO security_knowledge(
  knowledge_id, topic, vulnerability_class, ecosystem, framework, content,
  source_url, source_title, source_updated_at, provenance, confidence, content_hash, claims
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(content_hash) DO UPDATE SET
  topic = excluded.topic,
  vulnerability_class = excluded.vulnerability_class,
  ecosystem = excluded.ecosystem,
  framework = excluded.framework,
  content = excluded.content,
  source_url = excluded.source_url,
  source_title = excluded.source_title,
  source_updated_at = excluded.source_updated_at,
  provenance = excluded.provenance,
  confidence = excluded.confidence,
  claims = excluded.claims,
  status = 'active',
  updated_at = CURRENT_TIMESTAMP;
