INSERT INTO repository_context_documents(context_id, repository, context_json, context_hash)
VALUES (?, ?, ?, ?)
ON CONFLICT(context_id) DO UPDATE SET
  context_json = excluded.context_json,
  context_hash = excluded.context_hash;
