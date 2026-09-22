PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS hunt_plan_versions (
  plan_id TEXT PRIMARY KEY,
  workflow_version TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(plan_id) REFERENCES hunt_plans(plan_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_hunt_plan_versions_lookup
  ON hunt_plan_versions(workflow_version, created_at);
