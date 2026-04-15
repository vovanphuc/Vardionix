CREATE TABLE IF NOT EXISTS findings (
  id TEXT PRIMARY KEY,
  rule_id TEXT NOT NULL,
  source TEXT NOT NULL DEFAULT 'semgrep',
  severity TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'open',
  title TEXT NOT NULL,
  message TEXT NOT NULL,
  file_path TEXT NOT NULL,
  start_line INTEGER NOT NULL,
  end_line INTEGER NOT NULL,
  start_col INTEGER,
  end_col INTEGER,
  code_snippet TEXT,
  metadata TEXT,
  confidence_score REAL,
  exploit_scenario TEXT,
  category TEXT,
  excluded INTEGER NOT NULL DEFAULT 0,
  exclusion_reason TEXT,
  policy_id TEXT,
  policy_title TEXT,
  policy_severity_override TEXT,
  remediation_guidance TEXT,
  first_seen_at TEXT NOT NULL,
  last_seen_at TEXT NOT NULL,
  dismissed_at TEXT,
  dismissed_reason TEXT
);

CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_file ON findings(file_path);
CREATE INDEX IF NOT EXISTS idx_findings_rule ON findings(rule_id);

CREATE TABLE IF NOT EXISTS jobs (
  id TEXT PRIMARY KEY,
  template_id TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  finding_id TEXT,
  created_at TEXT NOT NULL,
  completed_at TEXT,
  result TEXT,
  logs TEXT
);

CREATE TABLE IF NOT EXISTS scan_runs (
  id TEXT PRIMARY KEY,
  scope TEXT NOT NULL,
  target TEXT NOT NULL,
  started_at TEXT NOT NULL,
  completed_at TEXT,
  total_findings INTEGER,
  findings_by_severity TEXT
);
