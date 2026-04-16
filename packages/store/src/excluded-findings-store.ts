import type Database from "better-sqlite3";
import type { ExcludedFinding, Severity } from "@vardionix/schemas";

export interface ExcludedFindingFilters {
  severity?: Severity;
  filePath?: string;
  ruleId?: string;
  limit?: number;
  offset?: number;
}

function rowToExcludedFinding(row: Record<string, unknown>): ExcludedFinding {
  return {
    kind: "excluded",
    id: row.id as string,
    ruleId: row.rule_id as string,
    source: row.source as string,
    severity: row.severity as ExcludedFinding["severity"],
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
    category: row.category as ExcludedFinding["category"],
    policyId: row.policy_id as string | null,
    policyTitle: row.policy_title as string | null,
    policySeverityOverride: row.policy_severity_override as ExcludedFinding["policySeverityOverride"],
    remediationGuidance: row.remediation_guidance as string | null,
    firstSeenAt: row.first_seen_at as string,
    lastSeenAt: row.last_seen_at as string,
    exclusionReason: row.exclusion_reason as string,
    excludedAt: row.excluded_at as string,
  };
}

export class ExcludedFindingsStore {
  constructor(private db: Database.Database) {}

  upsertFinding(finding: ExcludedFinding): void {
    const stmt = this.db.prepare(`
      INSERT INTO excluded_findings (
        id, rule_id, source, severity, title, message,
        file_path, start_line, end_line, start_col, end_col,
        code_snippet, metadata,
        confidence_score, exploit_scenario, category,
        policy_id, policy_title, policy_severity_override, remediation_guidance,
        first_seen_at, last_seen_at,
        exclusion_reason, excluded_at
      ) VALUES (
        @id, @ruleId, @source, @severity, @title, @message,
        @filePath, @startLine, @endLine, @startCol, @endCol,
        @codeSnippet, @metadata,
        @confidenceScore, @exploitScenario, @category,
        @policyId, @policyTitle, @policySeverityOverride, @remediationGuidance,
        @firstSeenAt, @lastSeenAt,
        @exclusionReason, @excludedAt
      )
      ON CONFLICT(id) DO UPDATE SET
        source = excluded.source,
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
        policy_id = excluded.policy_id,
        policy_title = excluded.policy_title,
        policy_severity_override = excluded.policy_severity_override,
        remediation_guidance = excluded.remediation_guidance,
        last_seen_at = excluded.last_seen_at,
        exclusion_reason = excluded.exclusion_reason,
        excluded_at = excluded.excluded_at
    `);

    stmt.run({
      id: finding.id,
      ruleId: finding.ruleId,
      source: finding.source,
      severity: finding.severity,
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
      exclusionReason: finding.exclusionReason,
      excludedAt: finding.excludedAt,
    });
  }

  upsertFindings(findings: ExcludedFinding[]): void {
    const transaction = this.db.transaction((items: ExcludedFinding[]) => {
      for (const finding of items) {
        this.upsertFinding(finding);
      }
    });
    transaction(findings);
  }

  getFinding(id: string): ExcludedFinding | null {
    const row = this.db.prepare("SELECT * FROM excluded_findings WHERE id = ?").get(id) as
      | Record<string, unknown>
      | undefined;
    return row ? rowToExcludedFinding(row) : null;
  }

  listFindings(filters: ExcludedFindingFilters = {}): ExcludedFinding[] {
    const conditions: string[] = [];
    const params: Record<string, unknown> = {};

    if (filters.severity) {
      conditions.push("severity = @severity");
      params.severity = filters.severity;
    }
    if (filters.filePath) {
      conditions.push("file_path = @filePath");
      params.filePath = filters.filePath;
    }
    if (filters.ruleId) {
      conditions.push("rule_id = @ruleId");
      params.ruleId = filters.ruleId;
    }

    let sql = "SELECT * FROM excluded_findings";
    if (conditions.length > 0) {
      sql += " WHERE " + conditions.join(" AND ");
    }
    sql += " ORDER BY excluded_at DESC";

    if (filters.limit) {
      sql += " LIMIT @limit";
      params.limit = filters.limit;
    }
    if (filters.offset) {
      sql += " OFFSET @offset";
      params.offset = filters.offset;
    }

    const rows = this.db.prepare(sql).all(params) as Record<string, unknown>[];
    return rows.map(rowToExcludedFinding);
  }

  deleteFinding(id: string): boolean {
    const result = this.db.prepare("DELETE FROM excluded_findings WHERE id = ?").run(id);
    return result.changes > 0;
  }

  deleteFindings(ids: string[]): void {
    if (ids.length === 0) return;

    const stmt = this.db.prepare("DELETE FROM excluded_findings WHERE id = ?");
    const transaction = this.db.transaction((items: string[]) => {
      for (const id of items) {
        stmt.run(id);
      }
    });
    transaction(ids);
  }
}
