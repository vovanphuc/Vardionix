import type Database from "better-sqlite3";
import type { ActiveFinding, FindingStatus, Severity } from "@vardionix/schemas";

export interface FindingFilters {
  status?: FindingStatus;
  severity?: Severity;
  filePath?: string;
  filePathPrefix?: string;
  ruleId?: string;
  limit?: number;
  offset?: number;
}

export interface FindingStats {
  total: number;
  bySeverity: Record<string, number>;
  byStatus: Record<string, number>;
}

function rowToFinding(row: Record<string, unknown>): ActiveFinding {
  return {
    kind: "active",
    id: row.id as string,
    ruleId: row.rule_id as string,
    source: row.source as string,
    severity: row.severity as ActiveFinding["severity"],
    status: row.status as ActiveFinding["status"],
    title: row.title as string,
    message: row.message as string,
    filePath: row.file_path as string,
    startLine: row.start_line as number,
    endLine: row.end_line as number,
    startCol: row.start_col as number | undefined,
    endCol: row.end_col as number | undefined,
    codeSnippet: row.code_snippet as string | undefined,
    metadata: row.metadata ? JSON.parse(row.metadata as string) : undefined,
    confidenceScore: row.confidence_score as number | null,
    exploitScenario: row.exploit_scenario as string | null,
    category: row.category as ActiveFinding["category"],
    policyId: row.policy_id as string | null,
    policyTitle: row.policy_title as string | null,
    policySeverityOverride: row.policy_severity_override as ActiveFinding["policySeverityOverride"],
    remediationGuidance: row.remediation_guidance as string | null,
    firstSeenAt: row.first_seen_at as string,
    lastSeenAt: row.last_seen_at as string,
    dismissedAt: row.dismissed_at as string | null,
    dismissedReason: row.dismissed_reason as string | null,
  };
}

export class FindingsStore {
  constructor(private db: Database.Database) {}

  upsertFinding(finding: ActiveFinding): void {
    const stmt = this.db.prepare(`
      INSERT INTO findings (
        id, rule_id, source, severity, status, title, message,
        file_path, start_line, end_line, start_col, end_col,
        code_snippet, metadata,
        confidence_score, exploit_scenario, category,
        policy_id, policy_title,
        policy_severity_override, remediation_guidance,
        first_seen_at, last_seen_at, dismissed_at, dismissed_reason
      ) VALUES (
        @id, @ruleId, @source, @severity, @status, @title, @message,
        @filePath, @startLine, @endLine, @startCol, @endCol,
        @codeSnippet, @metadata,
        @confidenceScore, @exploitScenario, @category,
        @policyId, @policyTitle,
        @policySeverityOverride, @remediationGuidance,
        @firstSeenAt, @lastSeenAt, @dismissedAt, @dismissedReason
      )
      ON CONFLICT(id) DO UPDATE SET
        severity = excluded.severity,
        title = excluded.title,
        message = excluded.message,
        file_path = excluded.file_path,
        start_line = excluded.start_line,
        end_line = excluded.end_line,
        start_col = excluded.start_col,
        end_col = excluded.end_col,
        code_snippet = excluded.code_snippet,
        metadata = excluded.metadata,
        confidence_score = excluded.confidence_score,
        exploit_scenario = excluded.exploit_scenario,
        category = excluded.category,
        status = excluded.status,
        policy_id = excluded.policy_id,
        policy_title = excluded.policy_title,
        policy_severity_override = excluded.policy_severity_override,
        remediation_guidance = excluded.remediation_guidance,
        last_seen_at = excluded.last_seen_at
    `);

    stmt.run({
      id: finding.id,
      ruleId: finding.ruleId,
      source: finding.source,
      severity: finding.severity,
      status: finding.status,
      title: finding.title,
      message: finding.message,
      filePath: finding.filePath,
      startLine: finding.startLine,
      endLine: finding.endLine,
      startCol: finding.startCol ?? null,
      endCol: finding.endCol ?? null,
      codeSnippet: finding.codeSnippet ?? null,
      metadata: finding.metadata ? JSON.stringify(finding.metadata) : null,
      confidenceScore: finding.confidenceScore,
      exploitScenario: finding.exploitScenario,
      category: finding.category,
      policyId: finding.policyId,
      policyTitle: finding.policyTitle,
      policySeverityOverride: finding.policySeverityOverride,
      remediationGuidance: finding.remediationGuidance,
      firstSeenAt: finding.firstSeenAt,
      lastSeenAt: finding.lastSeenAt,
      dismissedAt: finding.dismissedAt,
      dismissedReason: finding.dismissedReason,
    });
  }

  upsertFindings(findings: ActiveFinding[]): void {
    const transaction = this.db.transaction((items: ActiveFinding[]) => {
      for (const finding of items) {
        this.upsertFinding(finding);
      }
    });
    transaction(findings);
  }

  getFinding(id: string): ActiveFinding | null {
    const row = this.db.prepare(
      "SELECT * FROM findings WHERE id = ? AND COALESCE(excluded, 0) = 0",
    ).get(id) as
      | Record<string, unknown>
      | undefined;
    return row ? rowToFinding(row) : null;
  }

  listFindings(filters: FindingFilters = {}): ActiveFinding[] {
    const conditions = ["COALESCE(excluded, 0) = 0"];
    const params: Record<string, unknown> = {};

    if (filters.status) {
      conditions.push("status = @status");
      params.status = filters.status;
    }
    if (filters.severity) {
      conditions.push("severity = @severity");
      params.severity = filters.severity;
    }
    if (filters.filePath) {
      conditions.push("file_path = @filePath");
      params.filePath = filters.filePath;
    }
    if (filters.filePathPrefix) {
      conditions.push("file_path LIKE @filePathPrefix || '%'");
      params.filePathPrefix = filters.filePathPrefix;
    }
    if (filters.ruleId) {
      conditions.push("rule_id = @ruleId");
      params.ruleId = filters.ruleId;
    }

    let sql = "SELECT * FROM findings";
    if (conditions.length > 0) {
      sql += " WHERE " + conditions.join(" AND ");
    }
    sql += " ORDER BY last_seen_at DESC";

    if (filters.limit) {
      sql += " LIMIT @limit";
      params.limit = filters.limit;
    }
    if (filters.offset) {
      sql += " OFFSET @offset";
      params.offset = filters.offset;
    }

    const rows = this.db.prepare(sql).all(params) as Record<string, unknown>[];
    return rows.map(rowToFinding);
  }

  updateStatus(id: string, status: FindingStatus, reason?: string): boolean {
    const now = new Date().toISOString();
    let stmt;

    if (status === "dismissed") {
      stmt = this.db.prepare(
        "UPDATE findings SET status = ?, dismissed_at = ?, dismissed_reason = ? WHERE id = ? AND COALESCE(excluded, 0) = 0",
      );
      const result = stmt.run(status, now, reason ?? null, id);
      return result.changes > 0;
    }

    stmt = this.db.prepare(
      "UPDATE findings SET status = ?, dismissed_at = NULL, dismissed_reason = NULL WHERE id = ? AND COALESCE(excluded, 0) = 0",
    );
    const result = stmt.run(status, id);
    return result.changes > 0;
  }

  updatePolicyEnrichment(
    id: string,
    policyId: string,
    policyTitle: string,
    severityOverride: string | null,
    remediationGuidance: string,
  ): boolean {
    const stmt = this.db.prepare(`
      UPDATE findings SET
        policy_id = ?,
        policy_title = ?,
        policy_severity_override = ?,
        remediation_guidance = ?
      WHERE id = ? AND COALESCE(excluded, 0) = 0
    `);
    const result = stmt.run(policyId, policyTitle, severityOverride, remediationGuidance, id);
    return result.changes > 0;
  }

  getStats(): FindingStats {
    const total = (
      this.db.prepare("SELECT COUNT(*) as count FROM findings WHERE COALESCE(excluded, 0) = 0").get() as { count: number }
    ).count;

    const bySeverity: Record<string, number> = {};
    const sevRows = this.db
      .prepare("SELECT severity, COUNT(*) as count FROM findings WHERE COALESCE(excluded, 0) = 0 GROUP BY severity")
      .all() as { severity: string; count: number }[];
    for (const row of sevRows) {
      bySeverity[row.severity] = row.count;
    }

    const byStatus: Record<string, number> = {};
    const statRows = this.db
      .prepare("SELECT status, COUNT(*) as count FROM findings WHERE COALESCE(excluded, 0) = 0 GROUP BY status")
      .all() as { severity: string; count: number }[];
    for (const row of statRows) {
      byStatus[(row as unknown as { status: string }).status] = row.count;
    }

    return { total, bySeverity, byStatus };
  }

  deleteFinding(id: string): boolean {
    const result = this.db
      .prepare("DELETE FROM findings WHERE id = ? AND COALESCE(excluded, 0) = 0")
      .run(id);
    return result.changes > 0;
  }

  deleteFindings(ids: string[]): void {
    if (ids.length === 0) return;

    const stmt = this.db.prepare(
      "DELETE FROM findings WHERE id = ? AND COALESCE(excluded, 0) = 0",
    );
    const transaction = this.db.transaction((items: string[]) => {
      for (const id of items) {
        stmt.run(id);
      }
    });
    transaction(ids);
  }
}
