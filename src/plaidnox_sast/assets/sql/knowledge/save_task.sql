INSERT INTO hunt_tasks(plan_id, task_id, title, objective, task_json, state)
VALUES (?, ?, ?, ?, ?, 'planned')
ON CONFLICT(plan_id, task_id) DO UPDATE SET
  title = excluded.title,
  objective = excluded.objective,
  task_json = excluded.task_json,
  state = 'planned';
