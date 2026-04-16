import * as vscode from "vscode";
import { runVardionix } from "./runner";
import {
  createDiagnosticCollection,
  updateDiagnostics,
  type ExcludedFinding,
  type Finding,
} from "./diagnostics";
import { FindingsTreeProvider, FindingItem } from "./findings-tree";
import { createStatusBar, updateStatusBar, setStatusBarScanning } from "./status-bar";
import { ensureSemgrep } from "./semgrep-downloader";

let diagnosticCollection: vscode.DiagnosticCollection;
let findingsTreeProvider: FindingsTreeProvider;

export function activate(context: vscode.ExtensionContext): void {
  diagnosticCollection = createDiagnosticCollection();
  findingsTreeProvider = new FindingsTreeProvider();

  // Ensure Semgrep is available (downloads if needed, runs in background)
  ensureSemgrep(context.globalStorageUri);

  // Status bar
  const statusBar = createStatusBar();

  // Register tree view
  const treeView = vscode.window.createTreeView("vardionixFindings", {
    treeDataProvider: findingsTreeProvider,
    showCollapseAll: true,
  });

  // Register commands
  context.subscriptions.push(
    diagnosticCollection,
    statusBar,
    treeView,
    vscode.commands.registerCommand("vardionix.scanCurrentFile", scanCurrentFile),
    vscode.commands.registerCommand("vardionix.scanStagedFiles", scanStagedFiles),
    vscode.commands.registerCommand("vardionix.scanWorkspace", scanWorkspace),
    vscode.commands.registerCommand("vardionix.listFindings", listFindings),
    vscode.commands.registerCommand("vardionix.listExcludedFindings", listExcludedFindings),
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

// === Scan commands ===

async function scanCurrentFile(): Promise<void> {
  const editor = vscode.window.activeTextEditor;
  if (!editor) {
    vscode.window.showWarningMessage("Vardionix: No active file to scan.");
    return;
  }
  await scanFile(editor.document.uri.fsPath);
}

async function scanFile(filePath: string): Promise<void> {
  const cwd = getWorkspaceCwd();
  if (!cwd) return;

  setStatusBarScanning();

  await vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: "Vardionix",
      cancellable: false,
    },
    async (progress) => {
      progress.report({ message: "Scanning file..." });

      const result = await runVardionix(["scan", "file", filePath], cwd);

      if (!result.success) {
        vscode.window.showErrorMessage(`Vardionix: Scan failed — ${result.error}`);
        syncStatusBar();
        return;
      }

      const scanResult = result.data as { totalFindings: number; totalExcluded: number };

      progress.report({ message: "Loading results..." });
      await loadAndDisplayFindings(cwd);

      showScanSummary(scanResult.totalFindings, scanResult.totalExcluded, "file");
    },
  );
}

async function scanStagedFiles(): Promise<void> {
  const cwd = getWorkspaceCwd();
  if (!cwd) return;

  setStatusBarScanning();

  await vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: "Vardionix",
      cancellable: false,
    },
    async (progress) => {
      progress.report({ message: "Scanning staged files..." });

      const result = await runVardionix(["scan", "staged"], cwd);

      if (!result.success) {
        vscode.window.showErrorMessage(`Vardionix: Scan failed — ${result.error}`);
        syncStatusBar();
        return;
      }

      const scanResult = result.data as { totalFindings: number; totalExcluded: number };

      progress.report({ message: "Loading results..." });
      await loadAndDisplayFindings(cwd);

      showScanSummary(scanResult.totalFindings, scanResult.totalExcluded, "staged files");
    },
  );
}

async function scanWorkspace(): Promise<void> {
  const cwd = getWorkspaceCwd();
  if (!cwd) return;

  setStatusBarScanning();

  await vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: "Vardionix",
      cancellable: false,
    },
    async (progress) => {
      progress.report({ message: "Scanning workspace..." });

      const result = await runVardionix(["scan", "workspace"], cwd);

      if (!result.success) {
        vscode.window.showErrorMessage(`Vardionix: Scan failed — ${result.error}`);
        syncStatusBar();
        return;
      }

      const scanResult = result.data as { totalFindings: number; totalExcluded: number };

      progress.report({ message: "Loading results..." });
      await loadAndDisplayFindings(cwd);

      showScanSummary(scanResult.totalFindings, scanResult.totalExcluded, "workspace");
    },
  );
}

// === Finding commands ===

async function listFindings(): Promise<void> {
  const cwd = getWorkspaceCwd();
  if (!cwd) return;
  await loadAndDisplayFindings(cwd);
}

async function listExcludedFindings(): Promise<void> {
  const cwd = getWorkspaceCwd();
  if (!cwd) return;

  const result = await runVardionix(["findings", "list", "--excluded", "--workspace", cwd], cwd);
  if (!result.success) {
    vscode.window.showErrorMessage(`Vardionix: Failed to list excluded findings — ${result.error}`);
    return;
  }

  const findings = result.data as ExcludedFinding[];
  if (findings.length === 0) {
    vscode.window.showInformationMessage("Vardionix: No excluded findings.");
    return;
  }

  const picked = await vscode.window.showQuickPick(
    findings.map((f) => ({
      label: `$(filter) ${f.title}`,
      description: severityLabel(f.policySeverityOverride ?? f.severity),
      detail: `${f.filePath}:${f.startLine} — ${f.exclusionReason}`,
      finding: f,
    })),
    {
      placeHolder: "Select an excluded finding to view details",
      matchOnDetail: true,
    },
  );

  if (!picked) return;

  const panel = vscode.window.createWebviewPanel(
    "vardionixExcludedFinding",
    `Excluded: ${picked.finding.id}`,
    vscode.ViewColumn.Beside,
    {},
  );
  panel.webview.html = buildExcludedFindingHtml(picked.finding);
}

async function refreshFindings(): Promise<void> {
  const cwd = getWorkspaceCwd();
  if (!cwd) return;
  await loadAndDisplayFindings(cwd);
}

async function loadAndDisplayFindings(cwd: string): Promise<void> {
  const result = await runVardionix(
    ["findings", "list", "--open-only", "--workspace", cwd],
    cwd,
  );

  if (!result.success) {
    syncStatusBar();
    return;
  }

  const findings = result.data as Finding[];
  findingsTreeProvider.setFindings(findings);
  updateDiagnostics(diagnosticCollection, findings);
  syncStatusBar();
}

async function explainFinding(item?: FindingItem | { finding?: Finding }): Promise<void> {
  const cwd = getWorkspaceCwd();
  if (!cwd) return;

  let findingId: string | undefined;

  if (item instanceof FindingItem) {
    findingId = item.finding.id;
  } else if (item?.finding) {
    findingId = item.finding.id;
  } else {
    const findings = findingsTreeProvider.getFindings();
    if (findings.length === 0) {
      vscode.window.showInformationMessage("Vardionix: No findings available. Run a scan first.");
      return;
    }

    const picked = await vscode.window.showQuickPick(
      findings.map((f) => ({
        label: `$(info) ${f.title}`,
        description: severityLabel(f.policySeverityOverride ?? f.severity),
        detail: `${f.filePath}:${f.startLine}`,
        findingId: f.id,
      })),
      {
        placeHolder: "Select a finding to explain",
        matchOnDetail: true,
      },
    );

    if (!picked) return;
    findingId = picked.findingId;
  }

  const result = await runVardionix(["explain", findingId], cwd);

  if (!result.success) {
    vscode.window.showErrorMessage(`Vardionix: Failed to explain finding — ${result.error}`);
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
    codeContext?: {
      filePath: string;
      startLine: number;
      endLine: number;
      snippet: string;
    };
  };

  const panel = vscode.window.createWebviewPanel(
    "vardionixExplanation",
    `Vardionix: ${explanation.title}`,
    vscode.ViewColumn.Beside,
    {},
  );

  panel.webview.html = buildExplanationHtml(explanation);
}

async function dismissFinding(item?: FindingItem | { finding?: Finding }): Promise<void> {
  const cwd = getWorkspaceCwd();
  if (!cwd) return;

  let findingId: string | undefined;
  let findingTitle: string | undefined;

  if (item instanceof FindingItem) {
    findingId = item.finding.id;
    findingTitle = item.finding.title;
  } else if (item?.finding) {
    findingId = item.finding.id;
    findingTitle = item.finding.title;
  } else {
    const findings = findingsTreeProvider.getFindings();
    if (findings.length === 0) return;

    const picked = await vscode.window.showQuickPick(
      findings.map((f) => ({
        label: `$(close) ${f.title}`,
        description: severityLabel(f.policySeverityOverride ?? f.severity),
        detail: `${f.filePath}:${f.startLine}`,
        findingId: f.id,
        findingTitle: f.title,
      })),
      {
        placeHolder: "Select a finding to dismiss",
        matchOnDetail: true,
      },
    );

    if (!picked) return;
    findingId = picked.findingId;
    findingTitle = picked.findingTitle;
  }

  const reason = await vscode.window.showQuickPick(
    [
      { label: "$(check) False positive", value: "False positive" },
      { label: "$(shield) Accepted risk", value: "Accepted risk" },
      { label: "$(tools) Will fix later", value: "Will fix later" },
      { label: "$(note) Not applicable", value: "Not applicable" },
      { label: "$(edit) Custom reason...", value: "__custom__" },
    ],
    { placeHolder: `Dismiss "${findingTitle}" — select reason` },
  );

  if (!reason) return;

  let reasonText = reason.value;
  if (reasonText === "__custom__") {
    const custom = await vscode.window.showInputBox({
      prompt: "Enter dismissal reason",
      placeHolder: "e.g., Mitigated by WAF rules",
    });
    if (!custom) return;
    reasonText = custom;
  }

  const args = ["finding", "dismiss", findingId];
  if (reasonText) {
    args.push("--reason", reasonText);
  }

  const result = await runVardionix(args, cwd);

  if (result.success) {
    vscode.window.showInformationMessage(`Vardionix: Dismissed "${findingTitle}"`);
    await loadAndDisplayFindings(cwd);
  } else {
    vscode.window.showErrorMessage(`Vardionix: Failed to dismiss — ${result.error}`);
  }
}

async function showPolicy(): Promise<void> {
  const cwd = getWorkspaceCwd();
  if (!cwd) return;

  // Fetch policy list first for autocomplete
  const listResult = await runVardionix(["policy", "list"], cwd);

  let policyId: string | undefined;

  if (listResult.success && Array.isArray(listResult.data) && listResult.data.length > 0) {
    const policies = listResult.data as Array<{ id: string; title: string; category: string }>;
    const picked = await vscode.window.showQuickPick(
      policies.map((p) => ({
        label: `$(law) ${p.id}`,
        description: p.title,
        detail: p.category,
        policyId: p.id,
      })),
      {
        placeHolder: "Select a policy to view",
        matchOnDescription: true,
        matchOnDetail: true,
      },
    );
    if (!picked) return;
    policyId = picked.policyId;
  } else {
    // Fallback to manual input
    policyId = await vscode.window.showInputBox({
      prompt: "Enter policy ID",
      placeHolder: "e.g., SEC-GO-014, POL-A03-INJECTION",
    });
  }

  if (!policyId) return;

  const result = await runVardionix(["policy", "show", policyId], cwd);

  if (!result.success) {
    vscode.window.showErrorMessage(`Vardionix: Policy not found — ${policyId}`);
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
    vscode.window.showWarningMessage("Vardionix: Open a workspace folder first.");
    return undefined;
  }
  return folders[0].uri.fsPath;
}

function syncStatusBar(): void {
  updateStatusBar(findingsTreeProvider.getSeverityCounts());
}

function severityLabel(sev: string | null | undefined): string {
  if (!sev) return "";
  const icons: Record<string, string> = {
    critical: "$(error) Critical",
    high: "$(error) High",
    medium: "$(warning) Medium",
    low: "$(info) Low",
    info: "$(info) Info",
  };
  return icons[sev] ?? sev;
}

function showScanSummary(totalFindings: number, totalExcluded: number, scope: string): void {
  if (totalFindings === 0 && totalExcluded === 0) {
    vscode.window.showInformationMessage(`Vardionix: No issues found in ${scope}.`);
    return;
  }

  const counts = findingsTreeProvider.getSeverityCounts();
  const parts: string[] = [];

  const critical = counts.critical ?? 0;
  const high = counts.high ?? 0;
  const medium = counts.medium ?? 0;
  const low = (counts.low ?? 0) + (counts.info ?? 0);

  if (critical > 0) parts.push(`${critical} critical`);
  if (high > 0) parts.push(`${high} high`);
  if (medium > 0) parts.push(`${medium} medium`);
  if (low > 0) parts.push(`${low} low`);

  const findingsText = parts.length > 0 ? parts.join(", ") : `${totalFindings} finding(s)`;
  const excludedText = totalExcluded > 0 ? ` (${totalExcluded} filtered)` : "";

  if (critical > 0 || high > 0) {
    vscode.window.showWarningMessage(`Vardionix: ${findingsText}${excludedText} in ${scope}`);
  } else {
    vscode.window.showInformationMessage(`Vardionix: ${findingsText}${excludedText} in ${scope}`);
  }
}

// === Webview HTML builders ===

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
  codeContext?: {
    filePath: string;
    startLine: number;
    endLine: number;
    snippet: string;
  };
}): string {
  const policySection = explanation.policyContext
    ? `
    <section>
      <h2>Policy Context</h2>
      <div class="card">
        <div class="card-header">
          <span class="badge badge-info">${esc(explanation.policyContext.policyId)}</span>
          <span>${esc(explanation.policyContext.policyTitle)}</span>
        </div>
        <p>${esc(explanation.policyContext.remediationGuidance)}</p>
      </div>
    </section>`
    : "";

  const codeSection = explanation.codeContext
    ? `
    <section>
      <h2>Code Context</h2>
      <div class="file-ref">${esc(explanation.codeContext.filePath)}:${explanation.codeContext.startLine}-${explanation.codeContext.endLine}</div>
      <pre><code>${esc(explanation.codeContext.snippet)}</code></pre>
    </section>`
    : "";

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  ${webviewStyles()}
</head>
<body>
  <header>
    <div class="title-row">
      <h1>${esc(explanation.title)}</h1>
      ${severityBadge(explanation.effectiveSeverity)}
    </div>
    <div class="meta">${esc(explanation.findingId)}</div>
  </header>

  <section>
    <h2>Why It Matters</h2>
    <p>${esc(explanation.whyItMatters)}</p>
  </section>

  <section>
    <h2>What to Change</h2>
    <ul class="checklist">
      ${explanation.whatToChange.map((item) => `<li>${esc(item)}</li>`).join("\n      ")}
    </ul>
  </section>

  <section>
    <h2>Safe Pattern</h2>
    <pre><code>${esc(explanation.safeExample)}</code></pre>
  </section>

  ${codeSection}
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
  const refLinks = policy.references.length > 0
    ? policy.references.map((r) => `<li><a href="${esc(r)}">${esc(r)}</a></li>`).join("\n      ")
    : "<li class=\"empty\">No references</li>";

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  ${webviewStyles()}
</head>
<body>
  <header>
    <div class="title-row">
      <h1>${esc(policy.title)}</h1>
      <span class="badge badge-info">${esc(policy.id)}</span>
    </div>
    <div class="meta">${esc(policy.category)}</div>
  </header>

  <section>
    <h2>Description</h2>
    <p>${esc(policy.description)}</p>
  </section>

  <section>
    <h2>Remediation Guidance</h2>
    <p>${esc(policy.remediationGuidance)}</p>
  </section>

  <section>
    <h2>References</h2>
    <ul class="ref-list">
      ${refLinks}
    </ul>
  </section>
</body>
</html>`;
}

function buildExcludedFindingHtml(finding: ExcludedFinding): string {
  const severity = (finding.policySeverityOverride ?? finding.severity) as string;

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  ${webviewStyles()}
</head>
<body>
  <header>
    <div class="title-row">
      <h1>${esc(finding.title)}</h1>
      ${severityBadge(severity)}
    </div>
    <div class="meta">${esc(finding.id)} &middot; ${esc(finding.filePath)}:${finding.startLine}</div>
  </header>

  <section>
    <h2>Exclusion Reason</h2>
    <div class="card">
      <p>${esc(finding.exclusionReason)}</p>
    </div>
  </section>
</body>
</html>`;
}

function severityBadge(severity: string): string {
  return `<span class="badge badge-${esc(severity)}">${esc(severity.toUpperCase())}</span>`;
}

function webviewStyles(): string {
  return `<style>
    :root {
      --bg: var(--vscode-editor-background, #1e1e1e);
      --fg: var(--vscode-foreground, #cccccc);
      --fg-muted: var(--vscode-descriptionForeground, #999999);
      --link: var(--vscode-textLink-foreground, #4fc3f7);
      --border: var(--vscode-panel-border, #333333);
      --code-bg: var(--vscode-textCodeBlock-background, #2d2d2d);
      --card-bg: var(--vscode-editorWidget-background, #252526);
      --radius: 6px;
    }
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: var(--vscode-font-family, -apple-system, BlinkMacSystemFont, sans-serif);
      font-size: 13px;
      line-height: 1.6;
      color: var(--fg);
      background: var(--bg);
      padding: 24px;
      max-width: 720px;
    }

    header { margin-bottom: 24px; }
    .title-row { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }
    h1 { font-size: 1.4em; font-weight: 600; }
    h2 { font-size: 0.85em; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; color: var(--fg-muted); margin-bottom: 8px; }
    .meta { color: var(--fg-muted); font-size: 0.9em; margin-top: 4px; }

    section { margin-bottom: 24px; }
    p { margin-bottom: 8px; }

    .badge {
      display: inline-block;
      padding: 2px 10px;
      border-radius: 12px;
      font-size: 0.75em;
      font-weight: 700;
      letter-spacing: 0.04em;
      color: #fff;
      white-space: nowrap;
    }
    .badge-critical { background: #d32f2f; }
    .badge-high { background: #e53935; }
    .badge-medium { background: #ef6c00; }
    .badge-low { background: #2e7d32; }
    .badge-info { background: var(--link); color: #000; }

    pre {
      background: var(--code-bg);
      padding: 14px 16px;
      border-radius: var(--radius);
      overflow-x: auto;
      font-family: var(--vscode-editor-font-family, 'Fira Code', Consolas, monospace);
      font-size: 12px;
      line-height: 1.5;
      border: 1px solid var(--border);
    }
    code { font-family: inherit; }

    .card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      padding: 14px 16px;
    }
    .card-header { margin-bottom: 8px; display: flex; align-items: center; gap: 8px; }

    .file-ref {
      font-family: var(--vscode-editor-font-family, monospace);
      font-size: 0.85em;
      color: var(--link);
      margin-bottom: 8px;
    }

    ul { padding-left: 0; list-style: none; }
    .checklist li {
      position: relative;
      padding: 6px 0 6px 24px;
      border-bottom: 1px solid var(--border);
    }
    .checklist li:last-child { border-bottom: none; }
    .checklist li::before {
      content: "\\2192";
      position: absolute;
      left: 4px;
      color: var(--link);
      font-weight: bold;
    }

    .ref-list li {
      padding: 4px 0;
    }
    .ref-list .empty { color: var(--fg-muted); font-style: italic; }

    a { color: var(--link); text-decoration: none; }
    a:hover { text-decoration: underline; }
  </style>`;
}

function esc(text: string): string {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}
