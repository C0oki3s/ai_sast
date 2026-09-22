SELECT context_id, commit_sha
FROM context_bases
WHERE repository = ? AND context_id <> ?
ORDER BY created_at DESC, context_id DESC
LIMIT 1;
