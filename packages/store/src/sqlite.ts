import type { Database as SqlJsDatabase, Statement as SqlJsStatement } from "sql.js";

type SqlPrimitive = string | number | Uint8Array | null;
type SqlParams = SqlPrimitive[] | Record<string, SqlPrimitive> | null | undefined;

export interface StatementRunResult {
  changes: number;
}

export interface StatementLike {
  run(...params: unknown[]): StatementRunResult;
  get(...params: unknown[]): Record<string, unknown> | undefined;
  all(params?: Record<string, unknown>): Record<string, unknown>[];
}

export interface DatabaseLike {
  exec(sql: string): void;
  prepare(sql: string): StatementLike;
  transaction<T extends unknown[]>(fn: (...args: T) => void): (...args: T) => void;
  close(): void;
}

export class SqlJsDatabaseAdapter implements DatabaseLike {
  private dirty = false;
  private transactionDepth = 0;

  constructor(
    private readonly db: SqlJsDatabase,
    private readonly persistToDisk?: () => void,
  ) {}

  exec(sql: string): void {
    this.db.run(sql);
    if (isMutatingSql(sql)) {
      this.markDirty();
    }
  }

  prepare(sql: string): StatementLike {
    return new SqlJsStatementAdapter(this, this.db.prepare(sql));
  }

  transaction<T extends unknown[]>(fn: (...args: T) => void): (...args: T) => void {
    return (...args: T) => {
      if (this.transactionDepth > 0) {
        fn(...args);
        return;
      }

      const dirtyBefore = this.dirty;
      this.db.run("BEGIN");
      this.transactionDepth += 1;

      try {
        fn(...args);
        this.transactionDepth -= 1;
        this.db.run("COMMIT");
        if (this.dirty) {
          this.flush();
        }
      } catch (error) {
        this.transactionDepth -= 1;
        this.db.run("ROLLBACK");
        this.dirty = dirtyBefore;
        throw error;
      }
    };
  }

  close(): void {
    if (this.dirty) {
      this.flush();
    }
    this.db.close();
  }

  markDirty(changes = this.getChanges()): StatementRunResult {
    this.dirty = true;
    if (this.transactionDepth === 0) {
      this.flush();
    }
    return {
      changes,
    };
  }

  private flush(): void {
    this.persistToDisk?.();
    this.dirty = false;
  }

  private getChanges(): number {
    const result = this.db.exec("SELECT changes() AS changes");
    return (result[0]?.values?.[0]?.[0] as number | undefined) ?? 0;
  }
}

class SqlJsStatementAdapter implements StatementLike {
  constructor(
    private readonly database: SqlJsDatabaseAdapter,
    private readonly statement: SqlJsStatement,
  ) {}

  run(...params: unknown[]): StatementRunResult {
    try {
      this.bindParams(params);
      while (this.statement.step()) {
        // Drain rows for statements that also return values.
      }
      return this.database.markDirty();
    } finally {
      this.reset();
    }
  }

  get(...params: unknown[]): Record<string, unknown> | undefined {
    try {
      this.bindParams(params);
      if (!this.statement.step()) {
        return undefined;
      }
      return { ...this.statement.getAsObject() };
    } finally {
      this.reset();
    }
  }

  all(params?: Record<string, unknown>): Record<string, unknown>[] {
    try {
      this.bindParams(params === undefined ? [] : [params]);
      const rows: Record<string, unknown>[] = [];
      while (this.statement.step()) {
        rows.push({ ...this.statement.getAsObject() });
      }
      return rows;
    } finally {
      this.reset();
    }
  }

  private bindParams(params: unknown[]): void {
    const normalized = normalizeParams(params);
    if (normalized !== undefined) {
      this.statement.bind(normalized);
    }
  }

  private reset(): void {
    this.statement.reset();
    this.statement.freemem();
  }
}

function normalizeParams(params: unknown[]): SqlParams {
  if (params.length === 0) {
    return undefined;
  }

  if (params.length === 1) {
    const [single] = params;
    if (
      single === null ||
      Array.isArray(single)
    ) {
      return single as SqlParams;
    }

    if (
      single instanceof Uint8Array ||
      typeof single === "string" ||
      typeof single === "number"
    ) {
      return [single];
    }

    if (typeof single === "boolean") {
      return [single ? 1 : 0];
    }

    if (typeof single === "object") {
      return Object.fromEntries(
        Object.entries(single as Record<string, unknown>).map(([key, value]) => [
          key.startsWith("@") || key.startsWith(":") || key.startsWith("$")
            ? key
            : `@${key}`,
          normalizeValue(value),
        ]),
      );
    }
  }

  return params.map(normalizeValue) as SqlPrimitive[];
}

function normalizeValue(value: unknown): SqlPrimitive {
  if (value === undefined) {
    return null;
  }
  if (value === null || typeof value === "string" || typeof value === "number") {
    return value;
  }
  if (typeof value === "boolean") {
    return value ? 1 : 0;
  }
  if (value instanceof Uint8Array) {
    return value;
  }
  return String(value);
}

function isMutatingSql(sql: string): boolean {
  return /^(?:\s)*(insert|update|delete|create|drop|alter|pragma|replace|begin|commit|rollback)/i.test(
    sql,
  );
}
