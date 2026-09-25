BEGIN;

ALTER TABLE code_scanning_scan_runs
  ADD COLUMN IF NOT EXISTS scan_status VARCHAR(32) NOT NULL DEFAULT 'RUNNING',
  ADD COLUMN IF NOT EXISTS scan_parameters JSONB NOT NULL DEFAULT '{}'::jsonb,
  ADD COLUMN IF NOT EXISTS result_summary JSONB NOT NULL DEFAULT '{}'::jsonb,
  ADD COLUMN IF NOT EXISTS finished_at TIMESTAMPTZ;

CREATE TABLE IF NOT EXISTS code_scanning_scan_findings (
  scan_finding_id VARCHAR(64) PRIMARY KEY,
  tenant_id VARCHAR(64) NOT NULL,
  scan_id VARCHAR(64) NOT NULL REFERENCES code_scanning_scan_runs(scan_id) ON DELETE CASCADE,
  finding_id VARCHAR(64) REFERENCES code_scanning_findings(finding_id) ON DELETE SET NULL,
  fingerprint VARCHAR(128) NOT NULL,
  severity VARCHAR(32) NOT NULL,
  category VARCHAR(255) NOT NULL DEFAULT '',
  cwe_id INTEGER,
  owasp_category VARCHAR(255) NOT NULL DEFAULT '',
  report_schema_version INTEGER NOT NULL DEFAULT 1,
  report_data JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT uq_code_scanning_scan_finding UNIQUE (scan_id, fingerprint),
  CONSTRAINT ck_code_scanning_scan_finding_version CHECK (report_schema_version > 0),
  CONSTRAINT ck_code_scanning_scan_finding_cwe CHECK (cwe_id IS NULL OR cwe_id > 0)
);

CREATE INDEX IF NOT EXISTS ix_code_scanning_scan_finding_severity
  ON code_scanning_scan_findings(scan_id, severity);
CREATE INDEX IF NOT EXISTS ix_code_scanning_scan_finding_cwe
  ON code_scanning_scan_findings(tenant_id, cwe_id);

INSERT INTO code_scanning_schema_migrations(version, checksum)
VALUES ('0007_scan_finding_reports', 'managed-by-release-checksum')
ON CONFLICT (version) DO NOTHING;

COMMIT;
