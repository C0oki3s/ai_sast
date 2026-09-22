BEGIN;

CREATE TABLE IF NOT EXISTS code_scanning_schema_migrations (
  version VARCHAR(64) PRIMARY KEY,
  checksum VARCHAR(64) NOT NULL,
  applied_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS code_scanning_codebases (
  codebase_id VARCHAR(64) PRIMARY KEY,
  tenant_id VARCHAR(64) NOT NULL,
  external_key VARCHAR(512) NOT NULL,
  display_name VARCHAR(255) NOT NULL,
  status VARCHAR(32) NOT NULL DEFAULT 'active',
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT uq_code_scanning_codebase_key UNIQUE (tenant_id, external_key)
);
CREATE INDEX IF NOT EXISTS ix_code_scanning_codebases_tenant_id
  ON code_scanning_codebases(tenant_id);

CREATE TABLE IF NOT EXISTS code_scanning_snapshots (
  snapshot_id VARCHAR(64) PRIMARY KEY,
  tenant_id VARCHAR(64) NOT NULL,
  codebase_id VARCHAR(64) NOT NULL REFERENCES code_scanning_codebases(codebase_id) ON DELETE CASCADE,
  revision VARCHAR(128) NOT NULL,
  tree_hash VARCHAR(64) NOT NULL,
  state VARCHAR(32) NOT NULL DEFAULT 'indexed',
  parent_snapshot_id VARCHAR(64) REFERENCES code_scanning_snapshots(snapshot_id) ON DELETE SET NULL,
  context_version VARCHAR(64) NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT uq_code_scanning_snapshot_revision UNIQUE (codebase_id, revision)
);
CREATE INDEX IF NOT EXISTS ix_code_scanning_snapshots_tenant_id
  ON code_scanning_snapshots(tenant_id);
CREATE INDEX IF NOT EXISTS ix_code_scanning_snapshot_current
  ON code_scanning_snapshots(codebase_id, state, created_at);

CREATE TABLE IF NOT EXISTS code_scanning_source_files (
  source_file_id VARCHAR(64) PRIMARY KEY,
  snapshot_id VARCHAR(64) NOT NULL REFERENCES code_scanning_snapshots(snapshot_id) ON DELETE CASCADE,
  path VARCHAR(2048) NOT NULL,
  language VARCHAR(64) NOT NULL DEFAULT 'unknown',
  content_hash VARCHAR(64) NOT NULL,
  size_bytes INTEGER NOT NULL,
  storage_uri TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT uq_code_scanning_source_file_path UNIQUE (snapshot_id, path),
  CONSTRAINT ck_code_scanning_source_file_size CHECK (size_bytes >= 0)
);
CREATE INDEX IF NOT EXISTS ix_code_scanning_source_files_snapshot_id
  ON code_scanning_source_files(snapshot_id);
CREATE INDEX IF NOT EXISTS ix_code_scanning_source_files_content_hash
  ON code_scanning_source_files(content_hash);

CREATE TABLE IF NOT EXISTS code_scanning_symbols (
  symbol_version_id VARCHAR(64) PRIMARY KEY,
  symbol_id VARCHAR(64) NOT NULL,
  snapshot_id VARCHAR(64) NOT NULL REFERENCES code_scanning_snapshots(snapshot_id) ON DELETE CASCADE,
  source_file_id VARCHAR(64) NOT NULL REFERENCES code_scanning_source_files(source_file_id) ON DELETE CASCADE,
  stable_key VARCHAR(2300) NOT NULL,
  qualified_name VARCHAR(1024) NOT NULL,
  signature TEXT NOT NULL DEFAULT '',
  kind VARCHAR(64) NOT NULL,
  path VARCHAR(2048) NOT NULL,
  start_line INTEGER NOT NULL,
  end_line INTEGER NOT NULL,
  content_hash VARCHAR(64) NOT NULL,
  content TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT uq_code_scanning_symbol_stable_key UNIQUE (snapshot_id, stable_key)
);
CREATE INDEX IF NOT EXISTS ix_code_scanning_symbols_symbol_id
  ON code_scanning_symbols(symbol_id);
CREATE INDEX IF NOT EXISTS ix_code_scanning_symbols_content_hash
  ON code_scanning_symbols(content_hash);
CREATE INDEX IF NOT EXISTS ix_code_scanning_symbol_path
  ON code_scanning_symbols(snapshot_id, path, start_line);

CREATE TABLE IF NOT EXISTS code_scanning_edges (
  edge_id VARCHAR(64) PRIMARY KEY,
  snapshot_id VARCHAR(64) NOT NULL REFERENCES code_scanning_snapshots(snapshot_id) ON DELETE CASCADE,
  source_symbol_id VARCHAR(64) NOT NULL,
  target_symbol_id VARCHAR(64) NOT NULL,
  relation VARCHAR(64) NOT NULL,
  provenance VARCHAR(64) NOT NULL,
  confidence DOUBLE PRECISION NOT NULL,
  attributes JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT uq_code_scanning_edge UNIQUE (snapshot_id, source_symbol_id, target_symbol_id, relation),
  CONSTRAINT ck_code_scanning_edge_confidence CHECK (confidence >= 0 AND confidence <= 1)
);
CREATE INDEX IF NOT EXISTS ix_code_scanning_edge_reverse
  ON code_scanning_edges(snapshot_id, target_symbol_id, relation);

CREATE TABLE IF NOT EXISTS code_scanning_threat_statements (
  threat_statement_id VARCHAR(64) PRIMARY KEY,
  tenant_id VARCHAR(64) NOT NULL,
  codebase_id VARCHAR(64) NOT NULL REFERENCES code_scanning_codebases(codebase_id) ON DELETE CASCADE,
  category VARCHAR(128) NOT NULL,
  statement TEXT NOT NULL,
  provenance VARCHAR(128) NOT NULL,
  source_reference TEXT NOT NULL DEFAULT '',
  version INTEGER NOT NULL DEFAULT 1,
  status VARCHAR(32) NOT NULL DEFAULT 'active',
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS ix_code_scanning_threat_scope
  ON code_scanning_threat_statements(tenant_id, codebase_id, status);

CREATE TABLE IF NOT EXISTS code_scanning_security_memories (
  memory_id VARCHAR(64) PRIMARY KEY,
  tenant_id VARCHAR(64) NOT NULL,
  codebase_id VARCHAR(64) REFERENCES code_scanning_codebases(codebase_id) ON DELETE CASCADE,
  scope VARCHAR(64) NOT NULL,
  category VARCHAR(128) NOT NULL,
  statement TEXT NOT NULL,
  provenance VARCHAR(128) NOT NULL,
  status VARCHAR(32) NOT NULL DEFAULT 'pending',
  version INTEGER NOT NULL DEFAULT 1,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS ix_code_scanning_memory_scope
  ON code_scanning_security_memories(tenant_id, codebase_id, category, status);

CREATE TABLE IF NOT EXISTS code_scanning_security_knowledge (
  knowledge_id VARCHAR(64) PRIMARY KEY,
  tenant_id VARCHAR(64) NOT NULL DEFAULT 'global',
  topic TEXT NOT NULL,
  vulnerability_class VARCHAR(255) NOT NULL DEFAULT '',
  ecosystem VARCHAR(128) NOT NULL DEFAULT '',
  framework VARCHAR(128) NOT NULL DEFAULT '',
  content TEXT NOT NULL,
  source_url TEXT NOT NULL,
  source_title TEXT NOT NULL,
  source_updated_at VARCHAR(64) NOT NULL DEFAULT '',
  provenance VARCHAR(128) NOT NULL,
  confidence DOUBLE PRECISION NOT NULL,
  content_hash VARCHAR(64) NOT NULL,
  claims JSONB NOT NULL DEFAULT '[]'::jsonb,
  status VARCHAR(32) NOT NULL DEFAULT 'active',
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT uq_code_scanning_knowledge_hash UNIQUE (tenant_id, content_hash),
  CONSTRAINT ck_code_scanning_knowledge_confidence CHECK (confidence >= 0 AND confidence <= 1)
);
CREATE INDEX IF NOT EXISTS ix_code_scanning_knowledge_lookup
  ON code_scanning_security_knowledge(tenant_id, ecosystem, framework, status);

CREATE TABLE IF NOT EXISTS code_scanning_scan_runs (
  scan_id VARCHAR(64) PRIMARY KEY,
  tenant_id VARCHAR(64) NOT NULL,
  codebase_id VARCHAR(64) NOT NULL REFERENCES code_scanning_codebases(codebase_id) ON DELETE CASCADE,
  snapshot_id VARCHAR(64) NOT NULL REFERENCES code_scanning_snapshots(snapshot_id) ON DELETE RESTRICT,
  state VARCHAR(32) NOT NULL DEFAULT 'pending',
  mode VARCHAR(32) NOT NULL,
  workflow_version VARCHAR(64) NOT NULL,
  coverage_complete BOOLEAN NOT NULL DEFAULT FALSE,
  failure_code VARCHAR(128) NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS ix_code_scanning_scan_lookup
  ON code_scanning_scan_runs(tenant_id, codebase_id, created_at);

CREATE TABLE IF NOT EXISTS code_scanning_hunt_plans (
  plan_id VARCHAR(64) PRIMARY KEY,
  scan_id VARCHAR(64) NOT NULL REFERENCES code_scanning_scan_runs(scan_id) ON DELETE CASCADE,
  strategy TEXT NOT NULL,
  context_hash VARCHAR(64) NOT NULL,
  workflow_version VARCHAR(64) NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT uq_code_scanning_hunt_plan_context UNIQUE (scan_id, context_hash)
);

CREATE TABLE IF NOT EXISTS code_scanning_hunt_tasks (
  task_id VARCHAR(64) PRIMARY KEY,
  plan_id VARCHAR(64) NOT NULL REFERENCES code_scanning_hunt_plans(plan_id) ON DELETE CASCADE,
  task_key VARCHAR(255) NOT NULL,
  title TEXT NOT NULL,
  objective TEXT NOT NULL,
  task_data JSONB NOT NULL,
  state VARCHAR(32) NOT NULL DEFAULT 'planned',
  attempt_count INTEGER NOT NULL DEFAULT 0,
  lease_owner VARCHAR(128),
  lease_expires_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT uq_code_scanning_hunt_task_key UNIQUE (plan_id, task_key)
);
CREATE INDEX IF NOT EXISTS ix_code_scanning_hunt_task_lease
  ON code_scanning_hunt_tasks(state, lease_expires_at);

CREATE TABLE IF NOT EXISTS code_scanning_knowledge_usage (
  usage_id VARCHAR(64) PRIMARY KEY,
  scan_id VARCHAR(64) NOT NULL REFERENCES code_scanning_scan_runs(scan_id) ON DELETE CASCADE,
  task_id VARCHAR(64) NOT NULL REFERENCES code_scanning_hunt_tasks(task_id) ON DELETE CASCADE,
  knowledge_id VARCHAR(64) REFERENCES code_scanning_security_knowledge(knowledge_id) ON DELETE SET NULL,
  query TEXT NOT NULL,
  decision VARCHAR(64) NOT NULL,
  decision_confidence DOUBLE PRECISION NOT NULL,
  reason TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS ix_code_scanning_knowledge_usage_task
  ON code_scanning_knowledge_usage(scan_id, task_id);

CREATE TABLE IF NOT EXISTS code_scanning_model_invocations (
  invocation_id VARCHAR(64) PRIMARY KEY,
  scan_id VARCHAR(64) NOT NULL REFERENCES code_scanning_scan_runs(scan_id) ON DELETE CASCADE,
  task_id VARCHAR(64) REFERENCES code_scanning_hunt_tasks(task_id) ON DELETE SET NULL,
  stage VARCHAR(128) NOT NULL,
  model_tier VARCHAR(32) NOT NULL,
  provider_request_id VARCHAR(255) NOT NULL DEFAULT '',
  prompt_asset_version VARCHAR(64) NOT NULL,
  input_hash VARCHAR(64) NOT NULL,
  state VARCHAR(32) NOT NULL,
  input_tokens INTEGER NOT NULL DEFAULT 0,
  output_tokens INTEGER NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS ix_code_scanning_model_scan
  ON code_scanning_model_invocations(scan_id, stage, created_at);

CREATE TABLE IF NOT EXISTS code_scanning_prompt_cache_metrics (
  metric_id VARCHAR(64) PRIMARY KEY,
  invocation_id VARCHAR(64) NOT NULL UNIQUE REFERENCES code_scanning_model_invocations(invocation_id) ON DELETE CASCADE,
  cache_key_hash VARCHAR(64) NOT NULL,
  cache_hit BOOLEAN NOT NULL,
  cached_input_tokens INTEGER NOT NULL DEFAULT 0,
  tokens_avoided INTEGER NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS code_scanning_findings (
  finding_id VARCHAR(64) PRIMARY KEY,
  tenant_id VARCHAR(64) NOT NULL,
  codebase_id VARCHAR(64) NOT NULL REFERENCES code_scanning_codebases(codebase_id) ON DELETE CASCADE,
  scan_id VARCHAR(64) NOT NULL REFERENCES code_scanning_scan_runs(scan_id) ON DELETE CASCADE,
  fingerprint VARCHAR(128) NOT NULL,
  title TEXT NOT NULL,
  vulnerability_class VARCHAR(255) NOT NULL,
  severity VARCHAR(32) NOT NULL,
  state VARCHAR(32) NOT NULL,
  confidence DOUBLE PRECISION NOT NULL,
  summary TEXT NOT NULL,
  impact TEXT NOT NULL,
  remediation TEXT NOT NULL,
  validation JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT uq_code_scanning_finding_fingerprint UNIQUE (codebase_id, fingerprint)
);
CREATE INDEX IF NOT EXISTS ix_code_scanning_finding_scan
  ON code_scanning_findings(scan_id, state, severity);

CREATE TABLE IF NOT EXISTS code_scanning_finding_evidence (
  evidence_id VARCHAR(64) PRIMARY KEY,
  finding_id VARCHAR(64) NOT NULL REFERENCES code_scanning_findings(finding_id) ON DELETE CASCADE,
  sequence INTEGER NOT NULL,
  evidence_type VARCHAR(64) NOT NULL,
  path VARCHAR(2048) NOT NULL DEFAULT '',
  start_line INTEGER,
  end_line INTEGER,
  redacted_content TEXT NOT NULL,
  content_hash VARCHAR(64) NOT NULL,
  provenance VARCHAR(128) NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS ix_code_scanning_evidence_finding
  ON code_scanning_finding_evidence(finding_id, sequence);

CREATE TABLE IF NOT EXISTS code_scanning_finding_dependencies (
  finding_dependency_id VARCHAR(64) PRIMARY KEY,
  finding_id VARCHAR(64) NOT NULL REFERENCES code_scanning_findings(finding_id) ON DELETE CASCADE,
  dependency_type VARCHAR(64) NOT NULL,
  dependency_key VARCHAR(2300) NOT NULL,
  dependency_hash VARCHAR(64) NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT uq_code_scanning_finding_dependency UNIQUE (finding_id, dependency_type, dependency_key)
);
CREATE INDEX IF NOT EXISTS ix_code_scanning_finding_dependency_reverse
  ON code_scanning_finding_dependencies(dependency_type, dependency_key);

COMMIT;
