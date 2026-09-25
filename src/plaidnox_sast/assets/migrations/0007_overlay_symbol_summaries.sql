PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS overlay_symbol_summaries (
  overlay_id TEXT NOT NULL,
  symbol_id TEXT NOT NULL,
  summary_state TEXT NOT NULL CHECK(summary_state IN ('active', 'deleted')),
  content_hash TEXT,
  summary_json TEXT,
  PRIMARY KEY(overlay_id, symbol_id),
  FOREIGN KEY(overlay_id) REFERENCES pr_overlays(overlay_id) ON DELETE CASCADE,
  CHECK (
    (summary_state = 'active' AND content_hash IS NOT NULL AND summary_json IS NOT NULL)
    OR (summary_state = 'deleted' AND content_hash IS NULL AND summary_json IS NULL)
  )
);

CREATE INDEX IF NOT EXISTS idx_overlay_symbol_summaries_hash
  ON overlay_symbol_summaries(overlay_id, content_hash);
