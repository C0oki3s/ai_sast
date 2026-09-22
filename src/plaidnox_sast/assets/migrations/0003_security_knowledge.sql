PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS security_knowledge (
  knowledge_id TEXT PRIMARY KEY,
  topic TEXT NOT NULL,
  vulnerability_class TEXT NOT NULL DEFAULT '',
  ecosystem TEXT NOT NULL DEFAULT '',
  framework TEXT NOT NULL DEFAULT '',
  content TEXT NOT NULL,
  source_url TEXT NOT NULL,
  source_title TEXT NOT NULL,
  source_updated_at TEXT NOT NULL DEFAULT '',
  provenance TEXT NOT NULL,
  confidence REAL NOT NULL CHECK(confidence >= 0 AND confidence <= 1),
  content_hash TEXT NOT NULL UNIQUE,
  claims TEXT NOT NULL DEFAULT '[]',
  status TEXT NOT NULL DEFAULT 'active',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS knowledge_usage (
  usage_id TEXT PRIMARY KEY,
  repository TEXT NOT NULL,
  scan_id TEXT NOT NULL,
  task_id TEXT NOT NULL,
  query TEXT NOT NULL,
  knowledge_id TEXT,
  decision TEXT NOT NULL,
  decision_confidence REAL NOT NULL,
  reason TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(knowledge_id) REFERENCES security_knowledge(knowledge_id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS hunt_plans (
  plan_id TEXT PRIMARY KEY,
  repository TEXT NOT NULL,
  commit_sha TEXT NOT NULL,
  strategy TEXT NOT NULL,
  context_hash TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(repository, commit_sha, context_hash)
);

CREATE TABLE IF NOT EXISTS hunt_tasks (
  plan_id TEXT NOT NULL,
  task_id TEXT NOT NULL,
  title TEXT NOT NULL,
  objective TEXT NOT NULL,
  task_json TEXT NOT NULL,
  state TEXT NOT NULL DEFAULT 'planned',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY(plan_id, task_id),
  FOREIGN KEY(plan_id) REFERENCES hunt_plans(plan_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_security_knowledge_topic ON security_knowledge(topic, status);
CREATE INDEX IF NOT EXISTS idx_security_knowledge_framework ON security_knowledge(framework, ecosystem, status);
CREATE INDEX IF NOT EXISTS idx_knowledge_usage_scan ON knowledge_usage(repository, scan_id, task_id);
CREATE INDEX IF NOT EXISTS idx_hunt_plans_repository ON hunt_plans(repository, commit_sha);
