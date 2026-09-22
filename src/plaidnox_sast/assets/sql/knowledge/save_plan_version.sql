INSERT INTO hunt_plan_versions(plan_id, workflow_version)
VALUES (?, ?)
ON CONFLICT(plan_id) DO UPDATE SET workflow_version = excluded.workflow_version;
