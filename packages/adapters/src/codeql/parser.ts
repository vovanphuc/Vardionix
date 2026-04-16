import type { SarifLog, SarifResult, SarifRule } from "./types.js";

export interface ParsedCodeQLFinding {
  ruleId: string;
  filePath: string;
  startLine: number;
  endLine: number;
  startCol: number;
  endCol: number;
  message: string;
  severity: string;
  precision: string | null;
  tags: string[];
  metadata: Record<string, unknown>;
}

export function parseCodeQLSarif(sarif: SarifLog): ParsedCodeQLFinding[] {
  const findings: ParsedCodeQLFinding[] = [];

  for (const run of sarif.runs) {
    const rulesMap = new Map<string, SarifRule>();
    for (const rule of run.tool.driver.rules ?? []) {
      rulesMap.set(rule.id, rule);
    }

    for (const result of run.results) {
      const finding = parseResult(result, rulesMap);
      if (finding) findings.push(finding);
    }
  }

  return findings;
}

function parseResult(
  result: SarifResult,
  rulesMap: Map<string, SarifRule>,
): ParsedCodeQLFinding | null {
  const loc = result.locations?.[0]?.physicalLocation;
  if (!loc?.artifactLocation?.uri || !loc.region) return null;

  const rule = rulesMap.get(result.ruleId);
  const secSeverity = rule?.properties?.["security-severity"];
  const secScore = secSeverity ? parseFloat(secSeverity) : null;

  return {
    ruleId: result.ruleId,
    filePath: loc.artifactLocation.uri.replace(/%SRCROOT%\/?/, ""),
    startLine: loc.region.startLine,
    endLine: loc.region.endLine ?? loc.region.startLine,
    startCol: loc.region.startColumn ?? 1,
    endCol: loc.region.endColumn ?? 1,
    message: result.message.text,
    severity: mapSeverity(secScore, result.level),
    precision: rule?.properties?.precision ?? null,
    tags: rule?.properties?.tags ?? [],
    metadata: {
      codeqlRule: rule?.name ?? result.ruleId,
      precision: rule?.properties?.precision,
      securitySeverity: secSeverity,
      tags: rule?.properties?.tags,
    },
  };
}

function mapSeverity(secScore: number | null, level?: string): string {
  if (secScore !== null) {
    if (secScore >= 9.0) return "critical";
    if (secScore >= 7.0) return "high";
    if (secScore >= 4.0) return "medium";
    if (secScore >= 0.1) return "low";
    return "info";
  }
  switch (level) {
    case "error": return "high";
    case "warning": return "medium";
    case "note": return "low";
    default: return "info";
  }
}
