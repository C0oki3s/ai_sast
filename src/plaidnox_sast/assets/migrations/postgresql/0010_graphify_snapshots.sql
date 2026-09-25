BEGIN;

CREATE TABLE IF NOT EXISTS code_scanning_graphify_snapshots (
  graphify_record_id VARCHAR(64) PRIMARY KEY,
  tenant_id VARCHAR(64) NOT NULL,
  codebase_id VARCHAR(64) NOT NULL
    REFERENCES code_scanning_codebases(codebase_id) ON DELETE CASCADE,
  scan_id VARCHAR(64) NOT NULL UNIQUE
    REFERENCES code_scanning_scan_runs(scan_id) ON DELETE CASCADE,
  snapshot_id VARCHAR(64) NOT NULL
    REFERENCES code_scanning_snapshots(snapshot_id) ON DELETE CASCADE,
  graph_snapshot_id VARCHAR(64) NOT NULL,
  extractor_version VARCHAR(128) NOT NULL,
  source_hashes JSONB NOT NULL,
  unresolved_edges INTEGER NOT NULL CHECK (unresolved_edges >= 0),
  unindexed_files JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS ix_code_scanning_graphify_codebase_time
  ON code_scanning_graphify_snapshots(tenant_id, codebase_id, created_at);

CREATE TABLE IF NOT EXISTS code_scanning_graphify_nodes (
  graphify_record_id VARCHAR(64) NOT NULL
    REFERENCES code_scanning_graphify_snapshots(graphify_record_id) ON DELETE CASCADE,
  node_id VARCHAR(128) NOT NULL,
  path VARCHAR(2048) NOT NULL,
  line INTEGER NOT NULL CHECK (line > 0),
  label TEXT NOT NULL,
  source_hash VARCHAR(64) NOT NULL,
  PRIMARY KEY (graphify_record_id, node_id)
);

CREATE INDEX IF NOT EXISTS ix_code_scanning_graphify_node_path
  ON code_scanning_graphify_nodes(graphify_record_id, path, line);

CREATE TABLE IF NOT EXISTS code_scanning_graphify_edges (
  graphify_record_id VARCHAR(64) NOT NULL
    REFERENCES code_scanning_graphify_snapshots(graphify_record_id) ON DELETE CASCADE,
  edge_id VARCHAR(64) NOT NULL,
  source_id VARCHAR(128) NOT NULL,
  target_id VARCHAR(128) NOT NULL,
  relation VARCHAR(128) NOT NULL,
  provenance VARCHAR(64) NOT NULL,
  path VARCHAR(2048) NOT NULL,
  line INTEGER NOT NULL CHECK (line > 0),
  source_hash VARCHAR(64) NOT NULL,
  PRIMARY KEY (graphify_record_id, edge_id)
);

CREATE INDEX IF NOT EXISTS ix_code_scanning_graphify_edge_source
  ON code_scanning_graphify_edges(graphify_record_id, source_id);
CREATE INDEX IF NOT EXISTS ix_code_scanning_graphify_edge_target
  ON code_scanning_graphify_edges(graphify_record_id, target_id);

INSERT INTO code_scanning_schema_migrations(version, checksum)
VALUES ('0010_graphify_snapshots', 'managed-by-release-checksum')
ON CONFLICT (version) DO NOTHING;

COMMIT;
