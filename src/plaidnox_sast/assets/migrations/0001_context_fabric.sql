PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS context_bases (
  context_id TEXT PRIMARY KEY,
  repository TEXT NOT NULL,
  commit_sha TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(repository, commit_sha)
);

CREATE TABLE IF NOT EXISTS context_symbols (
  context_id TEXT NOT NULL,
  symbol_id TEXT NOT NULL,
  path TEXT NOT NULL,
  name TEXT NOT NULL,
  line INTEGER NOT NULL,
  content_hash TEXT NOT NULL,
  content TEXT NOT NULL,
  PRIMARY KEY(context_id, symbol_id),
  FOREIGN KEY(context_id) REFERENCES context_bases(context_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS context_edges (
  context_id TEXT NOT NULL,
  source_symbol TEXT NOT NULL,
  target_symbol TEXT NOT NULL,
  relation TEXT NOT NULL,
  PRIMARY KEY(context_id, source_symbol, target_symbol, relation),
  FOREIGN KEY(context_id) REFERENCES context_bases(context_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS pr_overlays (
  overlay_id TEXT PRIMARY KEY,
  base_context_id TEXT NOT NULL,
  repository TEXT NOT NULL,
  head_commit TEXT NOT NULL,
  state TEXT NOT NULL DEFAULT 'active',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(base_context_id) REFERENCES context_bases(context_id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS overlay_changes (
  overlay_id TEXT NOT NULL,
  symbol_id TEXT NOT NULL,
  change_type TEXT NOT NULL,
  PRIMARY KEY(overlay_id, symbol_id),
  FOREIGN KEY(overlay_id) REFERENCES pr_overlays(overlay_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS overlay_symbols (
  overlay_id TEXT NOT NULL,
  symbol_id TEXT NOT NULL,
  path TEXT NOT NULL,
  name TEXT NOT NULL,
  line INTEGER NOT NULL,
  content TEXT NOT NULL,
  PRIMARY KEY(overlay_id, symbol_id),
  FOREIGN KEY(overlay_id) REFERENCES pr_overlays(overlay_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS security_memories (
  memory_id TEXT PRIMARY KEY,
  repository TEXT NOT NULL,
  scope TEXT NOT NULL,
  category TEXT NOT NULL,
  statement TEXT NOT NULL,
  source TEXT NOT NULL,
  status TEXT NOT NULL,
  version INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS finding_dependencies (
  repository TEXT NOT NULL,
  fingerprint TEXT NOT NULL,
  symbol_id TEXT NOT NULL,
  context_id TEXT NOT NULL,
  PRIMARY KEY(repository, fingerprint, symbol_id, context_id),
  FOREIGN KEY(context_id) REFERENCES context_bases(context_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_context_symbols_path ON context_symbols(context_id, path);
CREATE INDEX IF NOT EXISTS idx_context_edges_target ON context_edges(context_id, target_symbol);
CREATE INDEX IF NOT EXISTS idx_security_memories_lookup ON security_memories(repository, category, status);
CREATE INDEX IF NOT EXISTS idx_finding_dependencies_symbol ON finding_dependencies(repository, symbol_id);
