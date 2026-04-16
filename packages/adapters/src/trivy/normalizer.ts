import { createHash } from "node:crypto";
import { FindingStatus, Severity, type ActiveFinding } from "@vardionix/schemas";
import type { ParsedTrivyVulnerability } from "./parser.js";

export function normalizeTrivyFindings(
  parsed: ParsedTrivyVulnerability[],
): ActiveFinding[] {
  const now = new Date().toISOString();

  return parsed.map((p) => ({
    kind: "active" as const,
    id: generateScaFindingId(p.vulnId, p.pkgName, p.lockfile),
    ruleId: p.vulnId,
    source: "trivy",
    severity: toSeverity(p.severity),
    status: FindingStatus.OPEN,
    title: p.title,
    message: p.description,
    filePath: p.lockfile,
    startLine: 0,
    endLine: 0,
    codeSnippet: undefined,
    metadata: {
      vulnerabilityId: p.vulnId,
      pkgName: p.pkgName,
      pkgVersion: p.pkgVersion,
      fixedVersion: p.fixedVersion,
      ecosystem: p.ecosystem,
      lockfile: p.lockfile,
      cvssScore: p.cvssScore,
      cweIds: p.cweIds,
      references: p.references,
      primaryUrl: p.primaryUrl,
      publishedDate: p.publishedDate,
      status: p.status,
    },
    confidenceScore: 0.95,
    exploitScenario: null,
    category: "other" as ActiveFinding["category"],
    policyId: null,
    policyTitle: null,
    policySeverityOverride: null,
    remediationGuidance: p.fixedVersion
      ? `Upgrade ${p.pkgName} from ${p.pkgVersion} to ${p.fixedVersion}`
      : `No fix available yet for ${p.pkgName}@${p.pkgVersion}`,
    firstSeenAt: now,
    lastSeenAt: now,
    dismissedAt: null,
    dismissedReason: null,
  }));
}

function generateScaFindingId(
  vulnId: string,
  pkgName: string,
  lockfile: string,
): string {
  const hash = createHash("sha256")
    .update(`${vulnId}:${pkgName}:${lockfile}`)
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
  return map[raw] ?? Severity.INFO;
}
