SELECT knowledge_id, topic, vulnerability_class, ecosystem, framework, content,
       source_url, source_title, source_updated_at, provenance, confidence, content_hash, claims
FROM security_knowledge
WHERE status = 'active'
  AND (topic LIKE ? OR vulnerability_class LIKE ? OR ecosystem LIKE ? OR framework LIKE ? OR content LIKE ?)
ORDER BY confidence DESC, updated_at DESC
LIMIT ?;
