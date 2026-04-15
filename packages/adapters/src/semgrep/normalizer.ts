import { createHash } from "node:crypto";
import { FindingStatus, Severity, type Finding } from "@vardionix/schemas";
import type { ParsedSemgrepFinding } from "./parser.js";

export function generateFindingId(
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

export function normalizeFindings(
  parsed: ParsedSemgrepFinding[],
): Finding[] {
  const now = new Date().toISOString();

  return parsed.map((p) => ({
    id: generateFindingId(p.checkId, p.filePath, p.startLine),
    ruleId: p.checkId,
    source: "semgrep",
    severity: toSeverity(p.severity),
    status: FindingStatus.OPEN,
    title: formatTitle(p.checkId),
    message: p.message,
    filePath: p.filePath,
    startLine: p.startLine,
    endLine: p.endLine,
    startCol: p.startCol,
    endCol: p.endCol,
    codeSnippet: p.codeSnippet,
    metadata: p.metadata,
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

function formatTitle(checkId: string): string {
  // Convert "javascript.lang.security.audit.xss" to "Xss"
  // or keep last segment capitalized
  const parts = checkId.split(".");
  const last = parts[parts.length - 1];
  return last
    .split(/[-_]/)
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join(" ");
}
