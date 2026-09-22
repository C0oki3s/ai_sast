SELECT plans.plan_id, plans.strategy
FROM hunt_plans plans
JOIN hunt_plan_versions versions ON versions.plan_id = plans.plan_id
WHERE plans.repository = ?
  AND plans.commit_sha = ?
  AND versions.workflow_version = ?
ORDER BY versions.created_at DESC, plans.rowid DESC
LIMIT 1;
