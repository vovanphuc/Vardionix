import { readFileSync, existsSync } from "node:fs";
import type { ActiveFinding, Severity } from "@vardionix/schemas";
import type { FindingsStore } from "@vardionix/store";

export interface TriageFinding {
  id: string;
  ruleId: string;
  source: string;
  severity: Severity;
  effectiveSeverity: Severity;
  title: string;
  message: string;
  category: string;
  filePath: string;
  startLine: number;
  endLine: number;
  codeSnippet: string | undefined;
  codeContext: string | undefined;
  confidenceScore: number | null;
  policyId: string | null;
  remediationGuidance: string | null;
}

export interface TriageBatch {
  findings: TriageFinding[];
  total: number;
  offset: number;
  hasMore: boolean;
  summary: string;
}

export interface ScanSummaryResult {
  total: number;
  bySeverity: Record<string, number>;
  byStatus: Record<string, number>;
  byCategory: CategorySummary[];
  bySource: Record<string, number>;
  topFiles: FileSummary[];
}

export interface CategorySummary {
  category: string;
  count: number;
  severities: Record<string, number>;
}

export interface FileSummary {
  filePath: string;
  count: number;
  highestSeverity: string;
}

export interface FindingFixContext {
  findingId: string;
  finding: ActiveFinding;
  codeContext: string;
  surroundingCode: string;
  fixHints: string[];
}

export class TriageService {
  constructor(private findingsStore: FindingsStore) {}

  /**
   * Get a batch of findings with code context, ready for AI triage.
   * Optionally filter by category, severity, file path prefix, or source.
   */
  getTriageBatch(options: {
    category?: string;
    severity?: Severity;
    filePathPrefix?: string;
    source?: string;
    limit?: number;
    offset?: number;
  }): TriageBatch {
    const limit = Math.min(options.limit ?? 10, 50);
    const offset = options.offset ?? 0;

    // Build filters for the store query
    const filters: Record<string, unknown> = {
      status: "open",
      limit: limit + 1, // fetch one extra to know if there's more
      offset,
    };
    if (options.severity) filters.severity = options.severity;
    if (options.filePathPrefix) filters.filePathPrefix = options.filePathPrefix;

    let findings = this.findingsStore.listFindings(filters as never);

    // Apply additional filters not supported by store
    if (options.category) {
      findings = findings.filter((f) => f.category === options.category);
    }
    if (options.source) {
      findings = findings.filter((f) => f.source === options.source);
    }

    const hasMore = findings.length > limit;
    const batch = findings.slice(0, limit);

    const triageFindings = batch.map((f) => this.toTriageFinding(f));

    const total = this.findingsStore.getStats().total;

    return {
      findings: triageFindings,
      total,
      offset,
      hasMore,
      summary: this.buildBatchSummary(triageFindings),
    };
  }

  /**
   * Get a comprehensive scan summary with category breakdown,
   * file hotspots, and source distribution.
   */
  getScanSummary(filePathPrefix?: string): ScanSummaryResult {
    const filters: Record<string, unknown> = { status: "open" };
    if (filePathPrefix) filters.filePathPrefix = filePathPrefix;

    const findings = this.findingsStore.listFindings(filters as never);
    const stats = this.findingsStore.getStats();

    // Build category breakdown
    const categoryMap = new Map<string, { count: number; severities: Record<string, number> }>();
    const sourceMap = new Map<string, number>();
    const fileMap = new Map<string, { count: number; highestSeverity: string }>();

    const severityOrder: Record<string, number> = {
      critical: 4,
      high: 3,
      medium: 2,
      low: 1,
      info: 0,
    };

    for (const f of findings) {
      // Category stats
      const cat = f.category ?? "uncategorized";
      const catEntry = categoryMap.get(cat) ?? { count: 0, severities: {} };
      catEntry.count++;
      const sev = (f.policySeverityOverride ?? f.severity).toLowerCase();
      catEntry.severities[sev] = (catEntry.severities[sev] ?? 0) + 1;
      categoryMap.set(cat, catEntry);

      // Source stats
      const src = f.source ?? "semgrep";
      sourceMap.set(src, (sourceMap.get(src) ?? 0) + 1);

      // File stats
      const fileEntry = fileMap.get(f.filePath) ?? { count: 0, highestSeverity: "info" };
      fileEntry.count++;
      if ((severityOrder[sev] ?? 0) > (severityOrder[fileEntry.highestSeverity] ?? 0)) {
        fileEntry.highestSeverity = sev;
      }
      fileMap.set(f.filePath, fileEntry);
    }

    const byCategory = Array.from(categoryMap.entries())
      .map(([category, data]) => ({ category, ...data }))
      .sort((a, b) => b.count - a.count);

    const topFiles = Array.from(fileMap.entries())
      .map(([filePath, data]) => ({ filePath, ...data }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 20);

    return {
      total: stats.total,
      bySeverity: stats.bySeverity,
      byStatus: stats.byStatus,
      byCategory,
      bySource: Object.fromEntries(sourceMap),
      topFiles,
    };
  }

  /**
   * Get a single finding with extended code context for AI to generate a fix.
   */
  getFixContext(findingId: string): FindingFixContext | null {
    const finding = this.findingsStore.getFinding(findingId);
    if (!finding) return null;

    const codeContext = this.readCodeContext(finding.filePath, finding.startLine, finding.endLine, 5);
    const surroundingCode = this.readCodeContext(finding.filePath, finding.startLine, finding.endLine, 20);
    const fixHints = this.generateFixHints(finding);

    return {
      findingId: finding.id,
      finding,
      codeContext: codeContext ?? "",
      surroundingCode: surroundingCode ?? "",
      fixHints,
    };
  }

  /**
   * Batch dismiss findings with a common reason.
   */
  batchDismiss(
    findingIds: string[],
    reason: string,
  ): { dismissed: number; notFound: string[] } {
    const notFound: string[] = [];
    let dismissed = 0;

    for (const id of findingIds) {
      const success = this.findingsStore.updateStatus(id, "dismissed" as never, reason);
      if (success) {
        dismissed++;
      } else {
        notFound.push(id);
      }
    }

    return { dismissed, notFound };
  }

  /**
   * Batch reopen previously dismissed findings.
   */
  batchReopen(findingIds: string[]): { reopened: number; notFound: string[] } {
    const notFound: string[] = [];
    let reopened = 0;

    for (const id of findingIds) {
      const success = this.findingsStore.updateStatus(id, "open" as never);
      if (success) {
        reopened++;
      } else {
        notFound.push(id);
      }
    }

    return { reopened, notFound };
  }

  private toTriageFinding(f: ActiveFinding): TriageFinding {
    const codeContext = this.readCodeContext(f.filePath, f.startLine, f.endLine, 5);
    return {
      id: f.id,
      ruleId: f.ruleId,
      source: f.source,
      severity: f.severity,
      effectiveSeverity: (f.policySeverityOverride ?? f.severity) as Severity,
      title: f.title,
      message: f.message,
      category: f.category ?? "uncategorized",
      filePath: f.filePath,
      startLine: f.startLine,
      endLine: f.endLine,
      codeSnippet: f.codeSnippet,
      codeContext,
      confidenceScore: f.confidenceScore,
      policyId: f.policyId,
      remediationGuidance: f.remediationGuidance,
    };
  }

  private readCodeContext(
    filePath: string,
    startLine: number,
    endLine: number,
    contextLines: number,
  ): string | undefined {
    if (!existsSync(filePath)) return undefined;

    try {
      const content = readFileSync(filePath, "utf-8");
      const lines = content.split("\n");

      const from = Math.max(0, startLine - contextLines - 1);
      const to = Math.min(lines.length, endLine + contextLines);

      return lines
        .slice(from, to)
        .map((line, i) => {
          const lineNum = from + i + 1;
          const marker =
            lineNum >= startLine && lineNum <= endLine ? ">>>" : "   ";
          return `${marker} ${lineNum.toString().padStart(4)}| ${line}`;
        })
        .join("\n");
    } catch {
      return undefined;
    }
  }

  private generateFixHints(finding: ActiveFinding): string[] {
    const hints: string[] = [];

    if (finding.remediationGuidance) {
      hints.push(finding.remediationGuidance);
    }

    // Category-specific hints
    const categoryHints: Record<string, string[]> = {
      xss: [
        "Use context-aware output encoding (HTML, JS, URL, CSS)",
        "Consider using a templating engine with auto-escaping",
        "Use DOMPurify for HTML sanitization on the client side",
      ],
      "sql-injection": [
        "Use parameterized queries or prepared statements",
        "Use an ORM with query builder (Prisma, Sequelize, SQLAlchemy)",
        "Never concatenate user input into SQL strings",
      ],
      "command-injection": [
        "Use execFile() instead of exec() to avoid shell interpretation",
        "Validate input against an allowlist of safe values",
        "Use child_process.spawn with shell: false",
      ],
      ssrf: [
        "Validate URLs against an allowlist of permitted domains",
        "Block requests to private/internal IP ranges (10.x, 172.16-31.x, 192.168.x)",
        "Use a URL parser to check the hostname before making requests",
      ],
      "path-traversal": [
        "Use path.resolve() and verify the result is within the expected directory",
        "Reject paths containing '..' segments",
        "Use an allowlist of permitted file paths or directories",
      ],
      "open-redirect": [
        "Validate redirect URLs against an allowlist of permitted domains",
        "Use relative paths instead of absolute URLs for redirects",
        "Parse the URL and check the hostname before redirecting",
      ],
      "timing-attack": [
        "Use crypto.timingSafeEqual() for constant-time comparison",
        "Convert strings to Buffers before comparing",
      ],
      "prototype-pollution": [
        "Use Object.create(null) for lookup objects",
        "Validate property names against __proto__, constructor, prototype",
        "Use Map instead of plain objects for user-controlled keys",
      ],
    };

    const cat = (finding.category ?? "").toLowerCase();
    if (categoryHints[cat]) {
      hints.push(...categoryHints[cat]);
    }

    if (hints.length === 0) {
      hints.push(
        `Review the code at ${finding.filePath}:${finding.startLine}`,
        "Apply the principle of least privilege and input validation",
      );
    }

    return hints;
  }

  private buildBatchSummary(findings: TriageFinding[]): string {
    if (findings.length === 0) return "No findings to triage.";

    const categories = new Map<string, number>();
    const severities = new Map<string, number>();

    for (const f of findings) {
      categories.set(f.category, (categories.get(f.category) ?? 0) + 1);
      const sev = f.effectiveSeverity.toLowerCase();
      severities.set(sev, (severities.get(sev) ?? 0) + 1);
    }

    const catStr = Array.from(categories.entries())
      .sort((a, b) => b[1] - a[1])
      .map(([cat, n]) => `${cat}(${n})`)
      .join(", ");

    const sevStr = Array.from(severities.entries())
      .sort((a, b) => b[1] - a[1])
      .map(([sev, n]) => `${sev}(${n})`)
      .join(", ");

    return `${findings.length} findings — severities: ${sevStr} — categories: ${catStr}`;
  }
}
