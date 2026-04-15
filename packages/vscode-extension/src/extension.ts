import * as vscode from "vscode";
import { runVardionix } from "./runner";
import {
  createDiagnosticCollection,
  updateDiagnostics,
  type Finding,
} from "./diagnostics";
import { FindingsTreeProvider } from "./findings-tree";

let diagnosticCollection: vscode.DiagnosticCollection;
let findingsTreeProvider: FindingsTreeProvider;

export function activate(context: vscode.ExtensionContext): void {
  diagnosticCollection = createDiagnosticCollection();
  findingsTreeProvider = new FindingsTreeProvider();

  // Register tree view
  const treeView = vscode.window.createTreeView("vardionixFindings", {
    treeDataProvider: findingsTreeProvider,
    showCollapseAll: true,
  });

  // Register commands
  context.subscriptions.push(
    diagnosticCollection,
    treeView,
    vscode.commands.registerCommand("vardionix.scanCurrentFile", scanCurrentFile),
    vscode.commands.registerCommand("vardionix.scanStagedFiles", scanStagedFiles),
    vscode.commands.registerCommand("vardionix.scanWorkspace", scanWorkspace),
    vscode.commands.registerCommand("vardionix.listFindings", listFindings),
    vscode.commands.registerCommand("vardionix.explainFinding", explainFinding),
    vscode.commands.registerCommand("vardionix.dismissFinding", dismissFinding),
    vscode.commands.registerCommand("vardionix.showPolicy", showPolicy),
    vscode.commands.registerCommand("vardionix.refreshFindings", refreshFindings),
  );

  // Auto-scan on save if configured
  const config = vscode.workspace.getConfiguration("vardionix");
  if (config.get<boolean>("scanOnSave")) {
    context.subscriptions.push(
      vscode.workspace.onDidSaveTextDocument((doc) => {
        scanFile(doc.uri.fsPath);
      }),
    );
  }
}

export function deactivate(): void {
  diagnosticCollection?.dispose();
}

// === Command implementations ===

async function scanCurrentFile(): Promise<void> {
  const editor = vscode.window.activeTextEditor;
  if (!editor) {
    vscode.window.showWarningMessage("No active file to scan.");
    return;
  }

  await scanFile(editor.document.uri.fsPath);
}

async function scanFile(filePath: string): Promise<void> {
  const cwd = getWorkspaceCwd();
  if (!cwd) return;

  await vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: "Vardionix: Scanning file...",
      cancellable: false,
    },
    async () => {
      const result = await runVardionix(["scan", "file", filePath], cwd);

      if (!result.success) {
        vscode.window.showErrorMessage(
          `Vardionix scan failed: ${result.error}`,
        );
        return;
      }

      const scanResult = result.data as {
        totalFindings: number;
        findingIds: string[];
      };

      // Fetch full finding details
      await loadAndDisplayFindings(cwd);

      vscode.window.showInformationMessage(
        `Vardionix: Found ${scanResult.totalFindings} finding(s)`,
      );
    },
  );
}

async function scanStagedFiles(): Promise<void> {
  const cwd = getWorkspaceCwd();
  if (!cwd) return;

  await vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: "Vardionix: Scanning staged files...",
      cancellable: false,
    },
    async () => {
      const result = await runVardionix(["scan", "staged"], cwd);

      if (!result.success) {
        vscode.window.showErrorMessage(
          `Vardionix scan failed: ${result.error}`,
        );
        return;
      }

      const scanResult = result.data as { totalFindings: number };
      await loadAndDisplayFindings(cwd);

      vscode.window.showInformationMessage(
        `Vardionix: Found ${scanResult.totalFindings} finding(s) in staged files`,
      );
    },
  );
}

async function scanWorkspace(): Promise<void> {
  const cwd = getWorkspaceCwd();
  if (!cwd) return;

  await vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: "Vardionix: Scanning workspace...",
      cancellable: false,
    },
    async () => {
      const result = await runVardionix(["scan", "workspace"], cwd);

      if (!result.success) {
        vscode.window.showErrorMessage(
          `Vardionix scan failed: ${result.error}`,
        );
        return;
      }

      const scanResult = result.data as { totalFindings: number };
      await loadAndDisplayFindings(cwd);

      vscode.window.showInformationMessage(
        `Vardionix: Found ${scanResult.totalFindings} finding(s) in workspace`,
      );
    },
  );
}

async function listFindings(): Promise<void> {
  const cwd = getWorkspaceCwd();
  if (!cwd) return;

  await loadAndDisplayFindings(cwd);
}

async function refreshFindings(): Promise<void> {
  const cwd = getWorkspaceCwd();
  if (!cwd) return;

  await loadAndDisplayFindings(cwd);
}

async function loadAndDisplayFindings(cwd: string): Promise<void> {
  const result = await runVardionix(["findings", "list", "--open-only"], cwd);

  if (!result.success) {
    return;
  }

  const findings = result.data as Finding[];
  findingsTreeProvider.setFindings(findings);
  updateDiagnostics(diagnosticCollection, findings);
}

async function explainFinding(item?: { finding?: Finding }): Promise<void> {
  const cwd = getWorkspaceCwd();
  if (!cwd) return;

  let findingId: string | undefined;

  if (item?.finding) {
    findingId = item.finding.id;
  } else {
    // Pick from available findings
    const findings = findingsTreeProvider.getFindings();
    if (findings.length === 0) {
      vscode.window.showInformationMessage("No findings available. Run a scan first.");
      return;
    }

    const picked = await vscode.window.showQuickPick(
      findings.map((f) => ({
        label: `${f.id} - ${f.title}`,
        description: `${f.severity} | ${f.filePath}:${f.startLine}`,
        findingId: f.id,
      })),
      { placeHolder: "Select a finding to explain" },
    );

    if (!picked) return;
    findingId = picked.findingId;
  }

  const result = await runVardionix(["explain", findingId], cwd);

  if (!result.success) {
    vscode.window.showErrorMessage(
      `Failed to explain finding: ${result.error}`,
    );
    return;
  }

  const explanation = result.data as {
    findingId: string;
    title: string;
    severity: string;
    effectiveSeverity: string;
    whyItMatters: string;
    whatToChange: string[];
    safeExample: string;
    policyContext?: {
      policyId: string;
      policyTitle: string;
      remediationGuidance: string;
    };
  };

  // Show in a webview panel
  const panel = vscode.window.createWebviewPanel(
    "vardionixExplanation",
    `Vardionix: ${explanation.title}`,
    vscode.ViewColumn.Beside,
    {},
  );

  panel.webview.html = buildExplanationHtml(explanation);
}

async function dismissFinding(item?: { finding?: Finding }): Promise<void> {
  const cwd = getWorkspaceCwd();
  if (!cwd) return;

  let findingId: string | undefined;

  if (item?.finding) {
    findingId = item.finding.id;
  } else {
    const findings = findingsTreeProvider.getFindings();
    if (findings.length === 0) return;

    const picked = await vscode.window.showQuickPick(
      findings.map((f) => ({
        label: `${f.id} - ${f.title}`,
        description: `${f.severity}`,
        findingId: f.id,
      })),
      { placeHolder: "Select a finding to dismiss" },
    );

    if (!picked) return;
    findingId = picked.findingId;
  }

  const reason = await vscode.window.showInputBox({
    prompt: "Reason for dismissal (optional)",
    placeHolder: "e.g., False positive, Accepted risk",
  });

  const args = ["finding", "dismiss", findingId];
  if (reason) {
    args.push("--reason", reason);
  }

  const result = await runVardionix(args, cwd);

  if (result.success) {
    vscode.window.showInformationMessage(`Finding ${findingId} dismissed.`);
    await loadAndDisplayFindings(cwd);
  } else {
    vscode.window.showErrorMessage(`Failed to dismiss: ${result.error}`);
  }
}

async function showPolicy(): Promise<void> {
  const cwd = getWorkspaceCwd();
  if (!cwd) return;

  const policyId = await vscode.window.showInputBox({
    prompt: "Enter policy ID",
    placeHolder: "e.g., SEC-GO-014, POL-A03-INJECTION",
  });

  if (!policyId) return;

  const result = await runVardionix(["policy", "show", policyId], cwd);

  if (!result.success) {
    vscode.window.showErrorMessage(`Policy not found: ${policyId}`);
    return;
  }

  const policy = result.data as {
    id: string;
    title: string;
    description: string;
    category: string;
    remediationGuidance: string;
    references: string[];
  };

  const panel = vscode.window.createWebviewPanel(
    "vardionixPolicy",
    `Policy: ${policy.id}`,
    vscode.ViewColumn.Beside,
    {},
  );

  panel.webview.html = buildPolicyHtml(policy);
}

// === Helpers ===

function getWorkspaceCwd(): string | undefined {
  const folders = vscode.workspace.workspaceFolders;
  if (!folders || folders.length === 0) {
    vscode.window.showWarningMessage("No workspace folder open.");
    return undefined;
  }
  return folders[0].uri.fsPath;
}

function buildExplanationHtml(explanation: {
  findingId: string;
  title: string;
  severity: string;
  effectiveSeverity: string;
  whyItMatters: string;
  whatToChange: string[];
  safeExample: string;
  policyContext?: {
    policyId: string;
    policyTitle: string;
    remediationGuidance: string;
  };
}): string {
  const sevColor =
    explanation.effectiveSeverity === "critical" ||
    explanation.effectiveSeverity === "high"
      ? "#f44336"
      : explanation.effectiveSeverity === "medium"
        ? "#ff9800"
        : "#4caf50";

  const policySection = explanation.policyContext
    ? `
    <h2>Policy Context</h2>
    <p><strong>${explanation.policyContext.policyId}</strong> - ${explanation.policyContext.policyTitle}</p>
    <p>${explanation.policyContext.remediationGuidance}</p>
  `
    : "";

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <style>
    body { font-family: var(--vscode-font-family, sans-serif); padding: 20px; color: var(--vscode-foreground, #ccc); background: var(--vscode-editor-background, #1e1e1e); }
    h1 { font-size: 1.4em; }
    h2 { font-size: 1.1em; margin-top: 20px; border-bottom: 1px solid var(--vscode-panel-border, #444); padding-bottom: 4px; }
    .severity { display: inline-block; padding: 2px 8px; border-radius: 4px; color: white; font-weight: bold; background: ${sevColor}; }
    .finding-id { color: var(--vscode-textLink-foreground, #4fc3f7); }
    ul { padding-left: 20px; }
    li { margin: 4px 0; }
    code { background: var(--vscode-textCodeBlock-background, #2d2d2d); padding: 2px 6px; border-radius: 3px; }
    pre { background: var(--vscode-textCodeBlock-background, #2d2d2d); padding: 12px; border-radius: 4px; overflow-x: auto; }
  </style>
</head>
<body>
  <h1>${explanation.title}</h1>
  <p><span class="finding-id">${explanation.findingId}</span> &mdash; <span class="severity">${explanation.effectiveSeverity.toUpperCase()}</span></p>

  <h2>Why It Matters</h2>
  <p>${escapeHtml(explanation.whyItMatters)}</p>

  <h2>What to Change</h2>
  <ul>
    ${explanation.whatToChange.map((item) => `<li>${escapeHtml(item)}</li>`).join("\n    ")}
  </ul>

  <h2>Safe Pattern</h2>
  <pre><code>${escapeHtml(explanation.safeExample)}</code></pre>

  ${policySection}
</body>
</html>`;
}

function buildPolicyHtml(policy: {
  id: string;
  title: string;
  description: string;
  category: string;
  remediationGuidance: string;
  references: string[];
}): string {
  const refLinks = policy.references
    .map((r) => `<li><a href="${escapeHtml(r)}">${escapeHtml(r)}</a></li>`)
    .join("\n    ");

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <style>
    body { font-family: var(--vscode-font-family, sans-serif); padding: 20px; color: var(--vscode-foreground, #ccc); background: var(--vscode-editor-background, #1e1e1e); }
    h1 { font-size: 1.4em; }
    h2 { font-size: 1.1em; margin-top: 20px; border-bottom: 1px solid var(--vscode-panel-border, #444); padding-bottom: 4px; }
    .category { color: var(--vscode-textLink-foreground, #4fc3f7); }
    a { color: var(--vscode-textLink-foreground, #4fc3f7); }
  </style>
</head>
<body>
  <h1>${escapeHtml(policy.id)} - ${escapeHtml(policy.title)}</h1>
  <p class="category">${escapeHtml(policy.category)}</p>

  <h2>Description</h2>
  <p>${escapeHtml(policy.description)}</p>

  <h2>Remediation Guidance</h2>
  <p>${escapeHtml(policy.remediationGuidance)}</p>

  <h2>References</h2>
  <ul>
    ${refLinks || "<li>No references</li>"}
  </ul>
</body>
</html>`;
}

function escapeHtml(text: string): string {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}
