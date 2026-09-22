SELECT task_json
FROM hunt_tasks
WHERE plan_id = ?
ORDER BY task_id;
