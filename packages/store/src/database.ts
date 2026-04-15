import Database from "better-sqlite3";
import { existsSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";

// Inline migration SQL to avoid file-path issues when bundled
const MIGRATION_001 = `
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
`;

let db: Database.Database | null = null;

export function getDefaultDbPath(): string {
  const dir = join(homedir(), ".vardionix");
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true });
  }
  return join(dir, "findings.db");
}

export function getDatabase(dbPath?: string): Database.Database {
  if (db) return db;

  const path = dbPath ?? getDefaultDbPath();
  db = new Database(path);
  db.pragma("journal_mode = WAL");
  db.pragma("foreign_keys = ON");

  runMigrations(db);
  return db;
}

export function createInMemoryDatabase(): Database.Database {
  const memDb = new Database(":memory:");
  memDb.pragma("foreign_keys = ON");
  runMigrations(memDb);
  return memDb;
}

function runMigrations(database: Database.Database): void {
  database.exec(`
    CREATE TABLE IF NOT EXISTS schema_migrations (
      version INTEGER PRIMARY KEY,
      applied_at TEXT NOT NULL
    )
  `);

  const applied = new Set(
    database
      .prepare("SELECT version FROM schema_migrations")
      .all()
      .map((row) => (row as { version: number }).version),
  );

  if (!applied.has(1)) {
    database.exec(MIGRATION_001);
    database
      .prepare("INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)")
      .run(1, new Date().toISOString());
  }
}

export function closeDatabase(): void {
  if (db) {
    db.close();
    db = null;
  }
}
