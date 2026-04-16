import { createHash } from "node:crypto";
import { FindingStatus, Severity, type ActiveFinding } from "@vardionix/schemas";
import type { ParsedCodeQLFinding } from "./parser.js";

export function normalizeCodeQLFindings(
  parsed: ParsedCodeQLFinding[],
): ActiveFinding[] {
  const now = new Date().toISOString();

  return parsed.map((p) => ({
    kind: "active" as const,
    id: generateFindingId(p.ruleId, p.filePath, p.startLine),
    ruleId: p.ruleId,
    source: "codeql",
    severity: toSeverity(p.severity),
    status: FindingStatus.OPEN,
    title: formatTitle(p.ruleId),
    message: p.message,
    filePath: p.filePath,
    startLine: p.startLine,
    endLine: p.endLine,
    startCol: p.startCol,
    endCol: p.endCol,
    codeSnippet: undefined,
    metadata: p.metadata,
    confidenceScore: mapPrecision(p.precision),
    exploitScenario: null,
    category: inferCategory(p.tags),
    policyId: null,
    policyTitle: null,
    policySeverityOverride: null,
    remediationGuidance: null,
    firstSeenAt: now,
    lastSeenAt: now,
    dismissedAt: null,
    dismissedReason: null,
  }));
}

function generateFindingId(
  ruleId: string,
  filePath: string,
  startLine: number,
): string {
  const hash = createHash("sha256")
    .update(`${ruleId}:${filePath}:${startLine}`)
    .digest("hex")
    .slice(0, 12);
  return `F-${hash}`;
}

function toSeverity(raw: string): Severity {
  const map: Record<string, Severity> = {
    critical: Severity.CRITICAL,
    high: Severity.HIGH,
    medium: Severity.MEDIUM,
    low: Severity.LOW,
    info: Severity.INFO,
  };
  return map[raw.toLowerCase()] ?? Severity.INFO;
}

function mapPrecision(precision: string | null): number | null {
  switch (precision) {
    case "very-high": return 0.95;
    case "high": return 0.9;
    case "medium": return 0.7;
    case "low": return 0.5;
    default: return null;
  }
}

type FindingCategory = ActiveFinding["category"];

function inferCategory(tags: string[]): FindingCategory {
  for (const tag of tags) {
    if (tag.includes("cwe-089") || tag.includes("cwe-079") || tag.includes("cwe-078"))
      return "input-validation";
    if (tag.includes("cwe-287") || tag.includes("cwe-306"))
      return "auth-bypass";
    if (tag.includes("cwe-327") || tag.includes("cwe-328"))
      return "crypto-weakness";
    if (tag.includes("cwe-094") || tag.includes("cwe-502"))
      return "code-execution";
    if (tag.includes("cwe-200") || tag.includes("cwe-312"))
      return "data-exposure";
    if (tag.includes("cwe-352")) return "csrf";
    if (tag.includes("cwe-918")) return "ssrf";
    if (tag.includes("cwe-022")) return "path-traversal";
  }
  return "other";
}

function formatTitle(ruleId: string): string {
  // CodeQL rule IDs: "js/xss", "py/sql-injection"
  const parts = ruleId.split("/");
  const last = parts[parts.length - 1];
  return last
    .split(/[-_]/)
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join(" ");
}
