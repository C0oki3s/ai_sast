INSERT INTO hunt_plans(plan_id, repository, commit_sha, strategy, context_hash)
VALUES (?, ?, ?, ?, ?)
ON CONFLICT(repository, commit_sha, context_hash) DO UPDATE SET strategy = excluded.strategy;
