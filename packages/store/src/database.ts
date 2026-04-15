import Database from "better-sqlite3";
import { existsSync, mkdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { homedir } from "node:os";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));

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

  const migrationsDir = join(__dirname, "..", "src", "migrations");
  // Also check dist-relative path for when running from built code
  const distMigrationsDir = join(__dirname, "migrations");

  let migrationSql: string | null = null;

  if (existsSync(join(migrationsDir, "001-init.sql"))) {
    migrationSql = readFileSync(join(migrationsDir, "001-init.sql"), "utf-8");
  } else if (existsSync(join(distMigrationsDir, "001-init.sql"))) {
    migrationSql = readFileSync(
      join(distMigrationsDir, "001-init.sql"),
      "utf-8",
    );
  }

  if (migrationSql && !applied.has(1)) {
    database.exec(migrationSql);
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
