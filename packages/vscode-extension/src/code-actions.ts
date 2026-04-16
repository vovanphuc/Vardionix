import * as vscode from "vscode";

interface VardionixDiagnosticData {
  findingId: string;
  policyId?: string | null;
  filePath: string;
}

function getDiagnosticData(diagnostic: vscode.Diagnostic): VardionixDiagnosticData | undefined {
  const data = (diagnostic as vscode.Diagnostic & { data?: unknown }).data;
  if (!data || typeof data !== "object") {
    return undefined;
  }

  const candidate = data as Partial<VardionixDiagnosticData>;
  if (!candidate.findingId || !candidate.filePath) {
    return undefined;
  }

  return {
    findingId: candidate.findingId,
    policyId: candidate.policyId,
    filePath: candidate.filePath,
  };
}

export class VardionixCodeActionProvider implements vscode.CodeActionProvider {
  static readonly providedCodeActionKinds = [vscode.CodeActionKind.QuickFix];

  provideCodeActions(
    _document: vscode.TextDocument,
    _range: vscode.Range | vscode.Selection,
    context: vscode.CodeActionContext,
  ): vscode.CodeAction[] {
    const actions: vscode.CodeAction[] = [];

    for (const diagnostic of context.diagnostics) {
      if (diagnostic.source !== "vardionix") {
        continue;
      }

      const data = getDiagnosticData(diagnostic);
      if (!data) {
        continue;
      }

      actions.push(createQuickFix("Explain finding", "vardionix.explainFinding", diagnostic, {
        finding: { id: data.findingId },
      }));
      actions.push(createQuickFix("Fix with Claude Code", "vardionix.fixFindingWithClaude", diagnostic, {
        finding: { id: data.findingId },
      }));
      actions.push(createQuickFix("Fix with Codex", "vardionix.fixFindingWithCodex", diagnostic, {
        finding: { id: data.findingId },
      }));
      actions.push(createQuickFix("Dismiss finding", "vardionix.dismissFinding", diagnostic, {
        finding: { id: data.findingId },
      }));
      actions.push(createQuickFix("Rescan this file", "vardionix.rescanFindingFile", diagnostic, {
        filePath: data.filePath,
      }));

      if (data.policyId) {
        actions.push(createQuickFix("Show policy", "vardionix.showPolicy", diagnostic, {
          policyId: data.policyId,
        }));
      }
    }

    return actions;
  }
}

function createQuickFix(
  title: string,
  command: string,
  diagnostic: vscode.Diagnostic,
  argument: unknown,
): vscode.CodeAction {
  const action = new vscode.CodeAction(title, vscode.CodeActionKind.QuickFix);
  action.command = {
    command,
    title,
    arguments: [argument],
  };
  action.diagnostics = [diagnostic];
  action.isPreferred = command === "vardionix.rescanFindingFile";
  return action;
}
