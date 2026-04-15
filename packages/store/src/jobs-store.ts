import type Database from "better-sqlite3";
import type { Job } from "@vardionix/schemas";

function rowToJob(row: Record<string, unknown>): Job {
  return {
    id: row.id as string,
    templateId: row.template_id as string,
    status: row.status as Job["status"],
    findingId: row.finding_id as string | undefined,
    createdAt: row.created_at as string,
    completedAt: row.completed_at as string | null,
    result: row.result ? JSON.parse(row.result as string) : null,
    logs: row.logs as string | null,
  };
}

export class JobsStore {
  constructor(private db: Database.Database) {}

  insertJob(job: Job): void {
    this.db
      .prepare(
        `INSERT INTO jobs (id, template_id, status, finding_id, created_at, completed_at, result, logs)
         VALUES (@id, @templateId, @status, @findingId, @createdAt, @completedAt, @result, @logs)`,
      )
      .run({
        id: job.id,
        templateId: job.templateId,
        status: job.status,
        findingId: job.findingId ?? null,
        createdAt: job.createdAt,
        completedAt: job.completedAt,
        result: job.result ? JSON.stringify(job.result) : null,
        logs: job.logs,
      });
  }

  getJob(id: string): Job | null {
    const row = this.db.prepare("SELECT * FROM jobs WHERE id = ?").get(id) as
      | Record<string, unknown>
      | undefined;
    return row ? rowToJob(row) : null;
  }

  updateJobStatus(
    id: string,
    status: Job["status"],
    logs?: string,
    result?: unknown,
  ): boolean {
    const completedAt =
      status === "completed" || status === "failed"
        ? new Date().toISOString()
        : null;

    const stmt = this.db.prepare(
      `UPDATE jobs SET status = ?, completed_at = ?, logs = COALESCE(?, logs), result = COALESCE(?, result) WHERE id = ?`,
    );
    const res = stmt.run(
      status,
      completedAt,
      logs ?? null,
      result ? JSON.stringify(result) : null,
      id,
    );
    return res.changes > 0;
  }

  listJobs(findingId?: string): Job[] {
    let sql = "SELECT * FROM jobs";
    const params: unknown[] = [];
    if (findingId) {
      sql += " WHERE finding_id = ?";
      params.push(findingId);
    }
    sql += " ORDER BY created_at DESC";
    const rows = this.db.prepare(sql).all(...params) as Record<string, unknown>[];
    return rows.map(rowToJob);
  }
}
