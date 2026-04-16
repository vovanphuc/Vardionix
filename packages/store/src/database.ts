import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";
import initSqlJsModule from "sql.js/dist/sql-asm.js";
import type { Database as SqlJsDatabase } from "sql.js";
import { SqlJsDatabaseAdapter, type DatabaseLike } from "./sqlite.js";

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
  confidence_score REAL,
  exploit_scenario TEXT,
  category TEXT,
  excluded INTEGER NOT NULL DEFAULT 0,
  exclusion_reason TEXT,
  dismissed_at TEXT,
  dismissed_reason TEXT
);

CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_file ON findings(file_path);
CREATE INDEX IF NOT EXISTS idx_findings_rule ON findings(rule_id);

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

const MIGRATION_002 = `
CREATE TABLE IF NOT EXISTS excluded_findings (
  id TEXT PRIMARY KEY,
  rule_id TEXT NOT NULL,
  source TEXT NOT NULL DEFAULT 'semgrep',
  severity TEXT NOT NULL,
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
  policy_id TEXT,
  policy_title TEXT,
  policy_severity_override TEXT,
  remediation_guidance TEXT,
  first_seen_at TEXT NOT NULL,
  last_seen_at TEXT NOT NULL,
  exclusion_reason TEXT NOT NULL,
  excluded_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_excluded_findings_severity ON excluded_findings(severity);
CREATE INDEX IF NOT EXISTS idx_excluded_findings_file ON excluded_findings(file_path);
CREATE INDEX IF NOT EXISTS idx_excluded_findings_rule ON excluded_findings(rule_id);
CREATE INDEX IF NOT EXISTS idx_excluded_findings_excluded_at ON excluded_findings(excluded_at);

INSERT OR REPLACE INTO excluded_findings (
  id, rule_id, source, severity, title, message,
  file_path, start_line, end_line, start_col, end_col,
  code_snippet, metadata, confidence_score, exploit_scenario, category,
  policy_id, policy_title, policy_severity_override, remediation_guidance,
  first_seen_at, last_seen_at, exclusion_reason, excluded_at
)
SELECT
  id, rule_id, source, severity, title, message,
  file_path, start_line, end_line, start_col, end_col,
  code_snippet, metadata, confidence_score, exploit_scenario, category,
  policy_id, policy_title, policy_severity_override, remediation_guidance,
  first_seen_at, last_seen_at,
  COALESCE(exclusion_reason, 'Excluded during scan filtering'),
  COALESCE(last_seen_at, first_seen_at)
FROM findings
WHERE COALESCE(excluded, 0) = 1;

DELETE FROM findings WHERE COALESCE(excluded, 0) = 1;
`;

let dbState:
  | {
      path: string;
      promise: Promise<DatabaseLike>;
    }
  | null = null;
let sqlJsPromise: Promise<{
  Database: new (data?: ArrayLike<number> | null) => SqlJsDatabase;
}> | null = null;

export function getDefaultDbPath(): string {
  const dir = join(homedir(), ".vardionix");
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true });
  }
  return join(dir, "findings.db");
}

export async function getDatabase(dbPath?: string): Promise<DatabaseLike> {
  const path = dbPath ?? getDefaultDbPath();
  if (dbState?.path === path) {
    return dbState.promise;
  }

  if (dbState) {
    void dbState.promise.then((db) => db.close());
  }

  dbState = {
    path,
    promise: createDatabase(path),
  };
  return dbState.promise;
}

export async function createInMemoryDatabase(): Promise<DatabaseLike> {
  const SQL = await getSqlJs();
  const memDb = new SQL.Database();
  const database = new SqlJsDatabaseAdapter(memDb);
  runMigrations(database);
  return database;
}

function runMigrations(database: DatabaseLike): void {
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

  if (!applied.has(2)) {
    database.exec(MIGRATION_002);
    database
      .prepare("INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)")
      .run(2, new Date().toISOString());
  }
}

export function closeDatabase(): void {
  if (dbState) {
    void dbState.promise.then((db) => db.close());
    dbState = null;
  }
}

async function createDatabase(dbPath: string): Promise<DatabaseLike> {
  const SQL = await getSqlJs();
  const data = existsSync(dbPath) ? readFileSync(dbPath) : undefined;
  const sqlJsDb = new SQL.Database(data);
  const database = new SqlJsDatabaseAdapter(sqlJsDb, () => {
    writeFileSync(dbPath, Buffer.from(sqlJsDb.export()));
  });

  runMigrations(database);
  return database;
}

async function getSqlJs(): Promise<{
  Database: new (data?: ArrayLike<number> | null) => SqlJsDatabase;
}> {
  if (!sqlJsPromise) {
    sqlJsPromise = Promise.resolve(initSqlJsModule()).then((sqlJs) => ({
      Database: sqlJs.Database,
    }));
  }
  return sqlJsPromise;
}
