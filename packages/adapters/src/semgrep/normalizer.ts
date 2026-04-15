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
    confidenceScore: inferConfidence(p),
    exploitScenario: null,
    category: inferCategory(p.checkId),
    excluded: false,
    exclusionReason: null,
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

function inferConfidence(p: ParsedSemgrepFinding): number {
  const conf = p.metadata?.confidence;
  if (conf === "HIGH") return 0.9;
  if (conf === "MEDIUM") return 0.7;
  if (conf === "LOW") return 0.5;
  return 0.7; // default
}

type FindingCategory = Finding["category"];

function inferCategory(checkId: string): FindingCategory {
  const id = checkId.toLowerCase();
  if (id.includes("sql-injection") || id.includes("xss") || id.includes("command-injection") || id.includes("injection"))
    return "input-validation";
  if (id.includes("auth") || id.includes("session") || id.includes("password") || id.includes("reset-token"))
    return "auth-bypass";
  if (id.includes("crypto") || id.includes("cipher") || id.includes("hash"))
    return "crypto-weakness";
  if (id.includes("eval") || id.includes("deserialization") || id.includes("pickle") || id.includes("exec"))
    return "code-execution";
  if (id.includes("secret") || id.includes("hardcoded") || id.includes("credential") || id.includes("token"))
    return "data-exposure";
  if (id.includes("csrf")) return "csrf";
  if (id.includes("ssrf") || id.includes("request-forgery")) return "ssrf";
  if (id.includes("path-traversal") || id.includes("directory-traversal")) return "path-traversal";
  return "other";
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
