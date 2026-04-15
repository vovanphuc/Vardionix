import * as vscode from "vscode";

export interface Finding {
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
}

const SEVERITY_MAP: Record<string, vscode.DiagnosticSeverity> = {
  critical: vscode.DiagnosticSeverity.Error,
  high: vscode.DiagnosticSeverity.Error,
  medium: vscode.DiagnosticSeverity.Warning,
  low: vscode.DiagnosticSeverity.Information,
  info: vscode.DiagnosticSeverity.Hint,
};

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
    `[${finding.id}] ${finding.message}`,
    SEVERITY_MAP[effectiveSeverity] ?? vscode.DiagnosticSeverity.Warning,
  );

  diagnostic.source = "vardionix";
  diagnostic.code = finding.ruleId;

  if (finding.remediationGuidance) {
    diagnostic.message += `\n\nRemediation: ${finding.remediationGuidance}`;
  }

  return diagnostic;
}
