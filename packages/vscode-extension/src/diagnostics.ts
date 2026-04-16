import * as vscode from "vscode";

export interface Finding {
  kind: "active";
  id: string;
  ruleId: string;
  severity: string;
  status: string;
  title: string;
  message: string;
  filePath: string;
  startLine: number;
  endLine: number;
  startCol?: number;
  endCol?: number;
  policyId?: string | null;
  policySeverityOverride?: string | null;
  remediationGuidance?: string | null;
  pendingVerification?: boolean;
}

export interface ExcludedFinding {
  kind: "excluded";
  id: string;
  severity: string;
  title: string;
  filePath: string;
  startLine: number;
  exclusionReason: string;
  policySeverityOverride?: string | null;
}

const SEVERITY_MAP: Record<string, vscode.DiagnosticSeverity> = {
  critical: vscode.DiagnosticSeverity.Error,
  high: vscode.DiagnosticSeverity.Error,
  medium: vscode.DiagnosticSeverity.Warning,
  low: vscode.DiagnosticSeverity.Information,
  info: vscode.DiagnosticSeverity.Hint,
};

export const SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"] as const;
export type FindingsGroupingMode = "severity" | "file";
export type MinimumSeverityFilter = typeof SEVERITY_ORDER[number] | "all";

export function getEffectiveSeverity(finding: Finding | ExcludedFinding): string {
  return finding.policySeverityOverride ?? finding.severity;
}

export function meetsMinimumSeverity(
  finding: Finding,
  minimumSeverity: MinimumSeverityFilter,
): boolean {
  if (minimumSeverity === "all") {
    return true;
  }

  return severityRank(getEffectiveSeverity(finding)) >= severityRank(minimumSeverity);
}

export function severityRank(severity: string): number {
  const index = SEVERITY_ORDER.indexOf(severity as (typeof SEVERITY_ORDER)[number]);
  return index >= 0 ? index : 0;
}

export function createDiagnosticCollection(): vscode.DiagnosticCollection {
  return vscode.languages.createDiagnosticCollection("vardionix");
}

export function updateDiagnostics(
  collection: vscode.DiagnosticCollection,
  findings: Finding[],
): void {
  collection.clear();

  // Group findings by file
  const byFile = new Map<string, Finding[]>();
  for (const f of findings) {
    const filePath = f.filePath;
    if (!byFile.has(filePath)) {
      byFile.set(filePath, []);
    }
    byFile.get(filePath)!.push(f);
  }

  for (const [filePath, fileFindings] of byFile) {
    const uri = vscode.Uri.file(filePath);
    const diagnostics = fileFindings.map((f) => findingToDiagnostic(f));
    collection.set(uri, diagnostics);
  }
}

function findingToDiagnostic(finding: Finding): vscode.Diagnostic {
  const effectiveSeverity = finding.policySeverityOverride ?? finding.severity;
  const range = new vscode.Range(
    Math.max(0, finding.startLine - 1),
    Math.max(0, (finding.startCol ?? 1) - 1),
    Math.max(0, finding.endLine - 1),
    finding.endCol ? finding.endCol - 1 : Number.MAX_SAFE_INTEGER,
  );

  const diagnostic = new vscode.Diagnostic(
    range,
    finding.pendingVerification
      ? `[${finding.id}] Pending verification after edit. Save or wait for auto-rescan to confirm.\n\nPrevious finding: ${finding.message}`
      : `[${finding.id}] ${finding.message}`,
    finding.pendingVerification
      ? vscode.DiagnosticSeverity.Hint
      : SEVERITY_MAP[effectiveSeverity] ?? vscode.DiagnosticSeverity.Warning,
  );

  diagnostic.source = "vardionix";
  diagnostic.code = finding.ruleId;
  (diagnostic as vscode.Diagnostic & {
    data?: { findingId: string; policyId?: string | null; filePath: string };
  }).data = {
    findingId: finding.id,
    policyId: finding.policyId,
    filePath: finding.filePath,
  };

  if (finding.remediationGuidance) {
    diagnostic.message += `\n\nRemediation: ${finding.remediationGuidance}`;
  }

  return diagnostic;
}
