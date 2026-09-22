SELECT knowledge_id, topic, vulnerability_class, ecosystem, framework, content,
       source_url, source_title, source_updated_at, provenance, confidence, content_hash
FROM security_knowledge
WHERE knowledge_id = ? AND status = 'active';
