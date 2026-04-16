import * as vscode from "vscode";
import { runVardionix } from "./runner";
import {
  createDiagnosticCollection,
  getEffectiveSeverity,
  meetsMinimumSeverity,
  type FindingsGroupingMode,
  type MinimumSeverityFilter,
  updateDiagnostics,
  type ExcludedFinding,
  type Finding,
} from "./diagnostics";
import { FindingsTreeProvider, FindingItem } from "./findings-tree";
import { VardionixCodeActionProvider } from "./code-actions";
import { createStatusBar, updateStatusBar, setStatusBarScanning } from "./status-bar";
import {
  ensureSemgrep,
  getLastSemgrepSetupError,
  hasSemgrepAvailable,
} from "./semgrep-downloader";
import {
  getMcpTargetLabel,
  installMcpServer,
  type McpClientTarget,
  verifyMcpServerRegistration,
} from "./mcp-register";

let diagnosticCollection: vscode.DiagnosticCollection;
let findingsTreeProvider: FindingsTreeProvider;
let findingsTreeView: vscode.TreeView<unknown> | undefined;
let semgrepStorageUri: vscode.Uri | undefined;
let extensionContext: vscode.ExtensionContext | undefined;
let outputChannel: vscode.OutputChannel | undefined;
let activeFindings: Finding[] = [];
const pendingVerificationFindingIds = new Set<string>();
const pendingRestoreTimers = new Map<string, ReturnType<typeof setTimeout>>();
const pendingIdleRescanTimers = new Map<string, ReturnType<typeof setTimeout>>();
const runningFileScans = new Map<string, Promise<void>>();
const viewState: {
  groupBy: FindingsGroupingMode;
  currentFileOnly: boolean;
  showDismissed: boolean;
  minimumSeverity: MinimumSeverityFilter;
  showPendingVerification: boolean;
} = {
  groupBy: "file",
  currentFileOnly: false,
  showDismissed: false,
  minimumSeverity: "all",
  showPendingVerification: true,
};

export function activate(context: vscode.ExtensionContext): void {
  diagnosticCollection = createDiagnosticCollection();
  findingsTreeProvider = new FindingsTreeProvider();
  findingsTreeProvider.setGrouping(viewState.groupBy);
  semgrepStorageUri = context.globalStorageUri;
  extensionContext = context;
  outputChannel = vscode.window.createOutputChannel("Vardionix");

  // Ensure Semgrep is available (downloads if needed, runs in background)
  ensureSemgrep(context.globalStorageUri);

  // Status bar
  const statusBar = createStatusBar();

  // Register tree view
  const treeView = vscode.window.createTreeView("vardionixFindings", {
    treeDataProvider: findingsTreeProvider,
    showCollapseAll: true,
  });
  findingsTreeView = treeView;

  // Register commands
  context.subscriptions.push(
    diagnosticCollection,
    statusBar,
    treeView,
    outputChannel,
    vscode.commands.registerCommand("vardionix.scanCurrentFile", scanCurrentFile),
    vscode.commands.registerCommand("vardionix.scanStagedFiles", scanStagedFiles),
    vscode.commands.registerCommand("vardionix.scanWorkspace", scanWorkspace),
    vscode.commands.registerCommand("vardionix.listFindings", listFindings),
    vscode.commands.registerCommand("vardionix.listExcludedFindings", listExcludedFindings),
    vscode.commands.registerCommand("vardionix.explainFinding", explainFinding),
    vscode.commands.registerCommand("vardionix.dismissFinding", dismissFinding),
    vscode.commands.registerCommand("vardionix.showPolicy", showPolicy),
    vscode.commands.registerCommand("vardionix.refreshFindings", refreshFindings),
    vscode.commands.registerCommand("vardionix.configureFindingsView", configureFindingsView),
    vscode.commands.registerCommand("vardionix.focusCurrentFile", toggleCurrentFileOnly),
    vscode.commands.registerCommand("vardionix.rescanFindingFile", rescanFindingFile),
    vscode.commands.registerCommand("vardionix.installMcpIntegration", installMcpIntegration),
    vscode.commands.registerCommand("vardionix.verifyMcpIntegration", verifyMcpIntegration),
    vscode.languages.registerCodeActionsProvider(
      { scheme: "file" },
      new VardionixCodeActionProvider(),
      { providedCodeActionKinds: VardionixCodeActionProvider.providedCodeActionKinds },
    ),
    vscode.workspace.onDidChangeTextDocument((event) => {
      void handleDocumentChange(event);
    }),
    vscode.workspace.onDidCloseTextDocument((document) => {
      cancelPendingIdleRescan(document.uri.fsPath);
      cancelPendingRestore(document.uri.fsPath);
      restoreHiddenFindingsForFile(document.uri.fsPath);
    }),
    vscode.window.onDidChangeActiveTextEditor(() => {
      applyFindingsToUi();
    }),
  );

  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument((doc) => {
      void handleDocumentSave(doc);
    }),
  );
}

export function deactivate(): void {
  for (const timer of pendingRestoreTimers.values()) {
    clearTimeout(timer);
  }
  pendingRestoreTimers.clear();
  for (const timer of pendingIdleRescanTimers.values()) {
    clearTimeout(timer);
  }
  pendingIdleRescanTimers.clear();
  diagnosticCollection?.dispose();
  outputChannel?.dispose();
}

// === Scan commands ===

async function scanCurrentFile(): Promise<void> {
  const editor = vscode.window.activeTextEditor;
  if (!editor) {
    vscode.window.showWarningMessage("Vardionix: No active file to scan.");
    return;
  }
  await triggerFileRescan(editor.document.uri.fsPath, "manual");
}

async function scanFile(
  filePath: string,
  options: {
    showProgress?: boolean;
    showSummary?: boolean;
    trigger?: "manual" | "save" | "idle" | "code-action";
  } = {},
): Promise<void> {
  const cwd = getWorkspaceCwd();
  if (!cwd) return;

  const {
    showProgress = true,
    showSummary = true,
    trigger = "manual",
  } = options;
  setStatusBarScanning();
  const beforeOpenCount = countOpenFindingsForFile(filePath);

  const runScan = async (progress?: { report: (value: { message?: string }) => void }) => {
    progress?.report({ message: "Scanning file..." });

    const result = await executeCli(["scan", "file", filePath], cwd, {
      label: `scan file ${filePath}`,
      revealOnError: true,
    });

    clearHiddenFindingsForFile(filePath);

    if (!result.success) {
      vscode.window.showErrorMessage(`Vardionix: Scan failed — ${result.error}`);
      applyFindingsToUi();
      return;
    }

    const scanResult = result.data as {
      totalFindings: number;
      totalExcluded: number;
      findingsBySeverity?: Record<string, number>;
    };

    progress?.report({ message: "Loading results..." });
    await loadAndDisplayFindings(cwd);
    notifyFileDelta(filePath, beforeOpenCount, countOpenFindingsForFile(filePath), trigger);

    if (showSummary) {
      showScanSummary(
        scanResult.totalFindings,
        scanResult.totalExcluded,
        "file",
        scanResult.findingsBySeverity,
      );
    }
  };

  if (!showProgress) {
    await runScan();
    return;
  }

  await vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: "Vardionix",
      cancellable: false,
    },
    runScan,
  );
}

async function scanStagedFiles(): Promise<void> {
  if (!(await ensureSemgrepForScan())) return;

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

      const result = await executeCli(["scan", "staged"], cwd, {
        label: "scan staged files",
        revealOnError: true,
      });

      if (!result.success) {
        vscode.window.showErrorMessage(formatScanError(result.error, "staged"));
        syncStatusBar();
        return;
      }

      const scanResult = result.data as {
        totalFindings: number;
        totalExcluded: number;
        findingsBySeverity?: Record<string, number>;
      };

      progress.report({ message: "Loading results..." });
      await loadAndDisplayFindings(cwd);

      showScanSummary(
        scanResult.totalFindings,
        scanResult.totalExcluded,
        "staged files",
        scanResult.findingsBySeverity,
      );
    },
  );
}

async function scanWorkspace(): Promise<void> {
  if (!(await ensureSemgrepForScan())) return;

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

      const result = await executeCli(["scan", "workspace"], cwd, {
        label: "scan workspace",
        revealOnError: true,
      });

      if (!result.success) {
        vscode.window.showErrorMessage(formatScanError(result.error, "workspace"));
        syncStatusBar();
        return;
      }

      const scanResult = result.data as {
        totalFindings: number;
        totalExcluded: number;
        findingsBySeverity?: Record<string, number>;
      };

      progress.report({ message: "Loading results..." });
      await loadAndDisplayFindings(cwd);

      showScanSummary(
        scanResult.totalFindings,
        scanResult.totalExcluded,
        "workspace",
        scanResult.findingsBySeverity,
      );
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

  const result = await executeCli(["findings", "list", "--excluded", "--workspace", cwd], cwd, {
    label: "list excluded findings",
    revealOnError: true,
  });
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

async function rescanFindingFile(input?: { filePath?: string } | FindingItem | { finding?: Finding }): Promise<void> {
  const filePath = resolveFindingFilePath(input);
  if (!filePath) {
    vscode.window.showWarningMessage("Vardionix: No file selected to rescan.");
    return;
  }

  await triggerFileRescan(filePath, "code-action");
}

async function loadAndDisplayFindings(cwd: string): Promise<void> {
  const args = ["findings", "list", "--workspace", cwd];
  const result = await executeCli(args, cwd, {
    label: "list findings",
    revealOnError: true,
  });

  if (!result.success) {
    syncStatusBar();
    return;
  }

  activeFindings = result.data as Finding[];
  pruneHiddenFindingIds();
  applyFindingsToUi();
}

async function explainFinding(item?: FindingItem | { finding?: Finding }): Promise<void> {
  const cwd = getWorkspaceCwd();
  if (!cwd) return;

  let findingId = resolveFindingId(item);

  if (!findingId) {
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

  const result = await executeCli(["explain", findingId], cwd, {
    label: `explain finding ${findingId}`,
    revealOnError: true,
  });

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

  let findingId = resolveFindingId(item);
  let findingTitle = resolveFinding(item)?.title;

  if (!findingId) {
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

  const result = await executeCli(args, cwd, {
    label: `dismiss finding ${findingId}`,
    revealOnError: true,
  });

  if (result.success) {
    vscode.window.showInformationMessage(`Vardionix: Dismissed "${findingTitle}"`);
    await loadAndDisplayFindings(cwd);
  } else {
    vscode.window.showErrorMessage(`Vardionix: Failed to dismiss — ${result.error}`);
  }
}

async function showPolicy(input?: { policyId?: string | null } | FindingItem | { finding?: Finding }): Promise<void> {
  const cwd = getWorkspaceCwd();
  if (!cwd) return;

  let policyId = resolvePolicyId(input);

  // Fetch policy list first for autocomplete
  const listResult = await executeCli(["policy", "list"], cwd, {
    label: "list policies",
    revealOnError: true,
  });

  if (!policyId && listResult.success && Array.isArray(listResult.data) && listResult.data.length > 0) {
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
  } else if (!policyId) {
    // Fallback to manual input
    policyId = await vscode.window.showInputBox({
      prompt: "Enter policy ID",
      placeHolder: "e.g., SEC-GO-014, POL-A03-INJECTION",
    });
  }

  if (!policyId) return;

  const result = await executeCli(["policy", "show", policyId], cwd, {
    label: `show policy ${policyId}`,
    revealOnError: true,
  });

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

async function installMcpIntegration(): Promise<void> {
  if (!extensionContext) {
    vscode.window.showErrorMessage("Vardionix: Extension context is not ready yet. Please retry.");
    return;
  }
  const context = extensionContext;

  const targets = await pickMcpTargets("Install MCP integration for");
  if (!targets) return;

  const results: string[] = [];

  for (const target of targets) {
    try {
      const result = installMcpServer(context, target);
      const state = result.verified ? "installed and verified" : "written but not verified";
      results.push(`${getMcpTargetLabel(target)}: ${state}`);
    } catch (error) {
      results.push(
        `${getMcpTargetLabel(target)}: failed — ${error instanceof Error ? error.message : String(error)}`,
      );
    }
  }

  const allVerified = targets.every((target) => verifyMcpServerRegistration(context, target));
  const message = `Vardionix: ${results.join(" | ")}`;

  if (allVerified) {
    vscode.window.showInformationMessage(message);
    return;
  }

  vscode.window.showWarningMessage(message);
}

async function verifyMcpIntegration(): Promise<void> {
  if (!extensionContext) {
    vscode.window.showErrorMessage("Vardionix: Extension context is not ready yet. Please retry.");
    return;
  }
  const context = extensionContext;

  const targets = await pickMcpTargets("Verify MCP integration for");
  if (!targets) return;

  const verified = targets.filter((target) => verifyMcpServerRegistration(context, target));
  const missing = targets.filter((target) => !verified.includes(target));

  if (missing.length === 0) {
    vscode.window.showInformationMessage(
      `Vardionix: MCP verified for ${verified.map(getMcpTargetLabel).join(" and ")}.`,
    );
    return;
  }

  vscode.window.showWarningMessage(
    `Vardionix: MCP missing for ${missing.map(getMcpTargetLabel).join(" and ")}. Use Install MCP to add it.`,
  );
}

// === Helpers ===

async function pickMcpTargets(placeHolder: string): Promise<McpClientTarget[] | undefined> {
  const picked = await vscode.window.showQuickPick(
    [
      {
        label: "$(hubot) Claude Code",
        description: "Write ~/.claude/settings.json",
        targets: ["claude"] as McpClientTarget[],
      },
      {
        label: "$(terminal-cmd) Codex",
        description: "Write ~/.codex/config.toml",
        targets: ["codex"] as McpClientTarget[],
      },
      {
        label: "$(plug) Claude Code + Codex",
        description: "Install MCP config for both agents",
        targets: ["claude", "codex"] as McpClientTarget[],
      },
    ],
    {
      placeHolder,
    },
  );

  return picked?.targets;
}

function getWorkspaceCwd(): string | undefined {
  const folders = vscode.workspace.workspaceFolders;
  if (!folders || folders.length === 0) {
    vscode.window.showWarningMessage("Vardionix: Open a workspace folder first.");
    return undefined;
  }
  return folders[0].uri.fsPath;
}

function getRelativeFileLabel(filePath: string): string {
  const cwd = getWorkspaceCwd();
  return cwd && filePath.startsWith(cwd) ? filePath.slice(cwd.length + 1) : filePath;
}

function getCurrentEditorFilePath(): string | undefined {
  const editor = vscode.window.activeTextEditor;
  if (!editor || editor.document.uri.scheme !== "file") {
    return undefined;
  }

  return editor.document.uri.fsPath;
}

function getRuntimeConfig(resource?: vscode.Uri) {
  const config = vscode.workspace.getConfiguration("vardionix", resource);
  return {
    hideTouchedFindingsImmediately: config.get<boolean>("hideTouchedFindingsImmediately", true),
    rescanOnIdle: config.get<boolean>("rescanOnIdle", true),
    rescanDebounceMs: Math.max(250, config.get<number>("rescanDebounceMs", 1500)),
    rescanOnSave: config.get<boolean>("rescanOnSave", true),
    legacyScanOnSave: config.get<boolean>("scanOnSave", false),
  };
}

async function executeCli(
  args: string[],
  cwd: string,
  options: {
    label: string;
    revealOnError?: boolean;
  },
) {
  appendOutput(`> vardionix ${args.join(" ")}`);
  appendOutput(`cwd: ${cwd}`);

  const result = await runVardionix(args, cwd);

  if (result.success) {
    appendOutput(`ok: ${options.label} (${describeCliResult(result.data)})`);
  } else {
    appendOutput(`error: ${options.label}`);
    appendOutput(result.error ?? "Unknown error");
    if (options.revealOnError) {
      outputChannel?.show(true);
    }
  }

  return result;
}

function appendOutput(message: string): void {
  outputChannel?.appendLine(`[${new Date().toISOString()}] ${message}`);
}

function describeCliResult(data: unknown): string {
  if (Array.isArray(data)) {
    return `${data.length} item(s)`;
  }
  if (data && typeof data === "object") {
    return "object";
  }
  return String(data ?? "empty");
}

async function ensureSemgrepForScan(): Promise<boolean> {
  if (!semgrepStorageUri) {
    vscode.window.showErrorMessage("Vardionix: Extension storage is not ready yet. Please retry.");
    return false;
  }

  await ensureSemgrep(semgrepStorageUri);

  if (hasSemgrepAvailable()) {
    return true;
  }

  const lastSetupError = getLastSemgrepSetupError();
  vscode.window.showErrorMessage(lastSetupError
    ? `Vardionix: Semgrep setup failed. ${lastSetupError}`
    : "Vardionix: Semgrep setup failed. The extension tried to install Semgrep automatically but it is still unavailable.",
  );
  return false;
}

function formatScanError(error: string | undefined, scope: "staged" | "workspace" | "file"): string {
  const message = error?.trim() || "Unknown error";

  if (message.includes("not a git repository")) {
    return "Vardionix: Scan Staged Files requires a Git repository.";
  }

  if (message.includes("Semgrep is not installed or not found in PATH")) {
    return "Vardionix: Semgrep is still unavailable after automatic setup. Please retry in a moment or set vardionix.semgrepPath manually.";
  }

  return `Vardionix: Scan failed — ${message}`;
}

function syncStatusBar(): void {
  updateStatusBar(findingsTreeProvider.getSeverityCounts());
}

async function configureFindingsView(): Promise<void> {
  const picked = await vscode.window.showQuickPick(
    [
      {
        label: `${viewState.currentFileOnly ? "$(check)" : "$(circle-large-outline)"} Focus Current File`,
        detail: viewState.currentFileOnly ? "Only show findings for the active editor." : "Show findings across the workspace.",
        action: "toggle-current-file" as const,
      },
      {
        label: `${viewState.showDismissed ? "$(check)" : "$(circle-large-outline)"} Show Dismissed Findings`,
        detail: viewState.showDismissed ? "Dismissed findings are visible." : "Dismissed findings are hidden.",
        action: "toggle-dismissed" as const,
      },
      {
        label: `${viewState.showPendingVerification ? "$(check)" : "$(circle-large-outline)"} Show Pending Verification`,
        detail: viewState.showPendingVerification ? "Touched findings stay visible as pending." : "Touched findings are hidden until confirmed.",
        action: "toggle-pending" as const,
      },
      {
        label: `Grouping: ${viewState.groupBy === "file" ? "File → Severity" : "Severity"}`,
        detail: "Choose how findings are grouped in the sidebar.",
        action: "grouping" as const,
      },
      {
        label: `Minimum Severity: ${severityLabel(viewState.minimumSeverity === "all" ? undefined : viewState.minimumSeverity) || "All"}`,
        detail: "Hide lower-severity findings from the sidebar and diagnostics.",
        action: "minimum-severity" as const,
      },
    ],
    {
      placeHolder: "Configure the Vardionix findings view",
      matchOnDescription: true,
      matchOnDetail: true,
    },
  );

  if (!picked) {
    return;
  }

  switch (picked.action) {
    case "toggle-current-file":
      viewState.currentFileOnly = !viewState.currentFileOnly;
      break;
    case "toggle-dismissed":
      viewState.showDismissed = !viewState.showDismissed;
      break;
    case "toggle-pending":
      viewState.showPendingVerification = !viewState.showPendingVerification;
      break;
    case "grouping":
      await pickGroupingMode();
      break;
    case "minimum-severity":
      await pickMinimumSeverity();
      break;
  }

  findingsTreeProvider.setGrouping(viewState.groupBy);
  applyFindingsToUi();
}

async function pickGroupingMode(): Promise<void> {
  const picked = await vscode.window.showQuickPick(
    [
      { label: "File → Severity", value: "file" as const },
      { label: "Severity", value: "severity" as const },
    ],
    {
      placeHolder: "Choose how to group findings",
    },
  );

  if (picked) {
    viewState.groupBy = picked.value;
  }
}

async function pickMinimumSeverity(): Promise<void> {
  const picked = await vscode.window.showQuickPick(
    [
      { label: "All severities", value: "all" as const },
      { label: "Critical only", value: "critical" as const },
      { label: "High and above", value: "high" as const },
      { label: "Medium and above", value: "medium" as const },
      { label: "Low and above", value: "low" as const },
      { label: "Info and above", value: "info" as const },
    ],
    {
      placeHolder: "Choose the minimum severity to show",
    },
  );

  if (picked) {
    viewState.minimumSeverity = picked.value;
  }
}

async function toggleCurrentFileOnly(): Promise<void> {
  viewState.currentFileOnly = !viewState.currentFileOnly;
  applyFindingsToUi();
}

async function handleDocumentChange(event: vscode.TextDocumentChangeEvent): Promise<void> {
  if (event.document.uri.scheme !== "file") {
    return;
  }

  if (event.contentChanges.length === 0) {
    if (!event.document.isDirty) {
      scheduleHiddenFindingsRestore(event.document.uri.fsPath);
    }
    return;
  }

  cancelPendingRestore(event.document.uri.fsPath);
  cancelPendingIdleRescan(event.document.uri.fsPath);
  const runtime = getRuntimeConfig(event.document.uri);

  const fileFindings = activeFindings.filter((finding) =>
    finding.filePath === event.document.uri.fsPath && finding.status === "open"
  );
  if (fileFindings.length === 0) {
    return;
  }

  let changed = false;
  for (const finding of fileFindings) {
    if (pendingVerificationFindingIds.has(finding.id)) {
      continue;
    }

    if (event.contentChanges.some((change) => overlapsFinding(change.range, finding))) {
      if (runtime.hideTouchedFindingsImmediately) {
        pendingVerificationFindingIds.add(finding.id);
      }
      changed = true;
    }
  }

  if (changed) {
    applyFindingsToUi();
  }

  if (runtime.rescanOnIdle && hasVisibleOrHiddenFindingsForFile(event.document.uri.fsPath)) {
    scheduleIdleFileRescan(event.document);
  }
}

async function handleDocumentSave(document: vscode.TextDocument): Promise<void> {
  if (document.uri.scheme !== "file") {
    return;
  }

  const filePath = document.uri.fsPath;
  const runtime = getRuntimeConfig(document.uri);
  cancelPendingIdleRescan(filePath);
  cancelPendingRestore(filePath);
  const shouldRefreshFile = runtime.legacyScanOnSave
    || (runtime.rescanOnSave && hasVisibleOrHiddenFindingsForFile(filePath));

  if (!shouldRefreshFile) {
    clearHiddenFindingsForFile(filePath);
    applyFindingsToUi();
    return;
  }

  await triggerFileRescan(filePath, "save");
}

function hasVisibleOrHiddenFindingsForFile(filePath: string): boolean {
  return activeFindings.some((finding) => finding.filePath === filePath && finding.status === "open")
    || Array.from(pendingVerificationFindingIds).some((id) =>
      activeFindings.some((finding) => finding.id === id && finding.filePath === filePath)
    );
}

function applyFindingsToUi(): void {
  const visibleFindings = getVisibleFindings();
  findingsTreeProvider.setGrouping(viewState.groupBy);
  findingsTreeProvider.setFindings(visibleFindings);
  updateDiagnostics(
    diagnosticCollection,
    visibleFindings.filter((finding) => finding.pendingVerification || finding.status === "open"),
  );
  updateFindingsViewDescription(visibleFindings);
  syncStatusBar();
}

function scheduleHiddenFindingsRestore(filePath: string): void {
  cancelPendingRestore(filePath);
  pendingRestoreTimers.set(
    filePath,
    setTimeout(() => {
      pendingRestoreTimers.delete(filePath);
      restoreHiddenFindingsForFile(filePath);
    }, 150),
  );
}

function cancelPendingRestore(filePath: string): void {
  const timer = pendingRestoreTimers.get(filePath);
  if (!timer) {
    return;
  }

  clearTimeout(timer);
  pendingRestoreTimers.delete(filePath);
}

function scheduleIdleFileRescan(document: vscode.TextDocument): void {
  const filePath = document.uri.fsPath;
  cancelPendingIdleRescan(filePath);
  const runtime = getRuntimeConfig(document.uri);
  pendingIdleRescanTimers.set(
    filePath,
    setTimeout(() => {
      pendingIdleRescanTimers.delete(filePath);
      if (document.isDirty) {
        appendOutput(`idle rescan skipped for ${filePath} because the document has unsaved changes`);
        return;
      }
      void triggerFileRescan(filePath, "idle");
    }, runtime.rescanDebounceMs),
  );
}

function cancelPendingIdleRescan(filePath: string): void {
  const timer = pendingIdleRescanTimers.get(filePath);
  if (!timer) {
    return;
  }

  clearTimeout(timer);
  pendingIdleRescanTimers.delete(filePath);
}

async function triggerFileRescan(
  filePath: string,
  trigger: "manual" | "save" | "idle" | "code-action",
): Promise<void> {
  const existing = runningFileScans.get(filePath);
  if (existing) {
    return existing;
  }

  const promise = (async () => {
    if (!(await ensureSemgrepForScan())) {
      return;
    }

    await scanFile(filePath, {
      showProgress: trigger === "manual" || trigger === "code-action",
      showSummary: trigger === "manual",
      trigger,
    });
  })().finally(() => {
    runningFileScans.delete(filePath);
  });

  runningFileScans.set(filePath, promise);
  return promise;
}

function getVisibleFindings(): Finding[] {
  const currentFilePath = viewState.currentFileOnly ? getCurrentEditorFilePath() : undefined;

  return activeFindings
    .map((finding) => ({
      ...finding,
      pendingVerification: pendingVerificationFindingIds.has(finding.id),
    }))
    .filter((finding) => viewState.showDismissed || finding.status === "open" || finding.pendingVerification)
    .filter((finding) => !currentFilePath || finding.filePath === currentFilePath)
    .filter((finding) => meetsMinimumSeverity(finding, viewState.minimumSeverity))
    .filter((finding) => viewState.showPendingVerification || !finding.pendingVerification);
}

function updateFindingsViewDescription(findings: Finding[]): void {
  if (!findingsTreeView) {
    return;
  }

  const parts: string[] = [];
  if (viewState.currentFileOnly) {
    parts.push("Current file");
  }
  if (viewState.minimumSeverity !== "all") {
    parts.push(`>= ${viewState.minimumSeverity}`);
  }
  if (viewState.showDismissed) {
    parts.push("Dismissed");
  }
  if (findings.some((finding) => finding.pendingVerification)) {
    parts.push("Pending");
  }

  findingsTreeView.description = parts.join(" · ");
  findingsTreeView.message = findings.length === 0
    ? viewState.currentFileOnly
      ? "No findings match the current file filters."
      : undefined
    : undefined;
}

function pruneHiddenFindingIds(): void {
  const activeFindingIds = new Set(activeFindings.map((finding) => finding.id));
  for (const id of Array.from(pendingVerificationFindingIds)) {
    if (!activeFindingIds.has(id)) {
      pendingVerificationFindingIds.delete(id);
    }
  }
}

function clearHiddenFindingsForFile(filePath: string): void {
  for (const finding of activeFindings) {
    if (finding.filePath === filePath) {
      pendingVerificationFindingIds.delete(finding.id);
    }
  }
}

function restoreHiddenFindingsForFile(filePath: string): void {
  const before = pendingVerificationFindingIds.size;
  clearHiddenFindingsForFile(filePath);
  if (pendingVerificationFindingIds.size !== before) {
    applyFindingsToUi();
  }
}

function overlapsFinding(range: vscode.Range, finding: Finding): boolean {
  const changeStartLine = range.start.line + 1;
  const changeEndLine = range.end.line + 1;
  return changeStartLine <= finding.endLine && changeEndLine >= finding.startLine;
}

function resolveFinding(input?: FindingItem | { finding?: Finding } | { finding?: { id?: string } } | { filePath?: string }): Finding | undefined {
  if (input instanceof FindingItem) {
    return input.finding;
  }

  const candidate = input as { finding?: { id?: string } } | undefined;
  const findingId = candidate?.finding?.id;
  if (!findingId) {
    return undefined;
  }

  return activeFindings.find((finding) => finding.id === findingId)
    ?? findingsTreeProvider.getFindings().find((finding) => finding.id === findingId);
}

function resolveFindingId(input?: FindingItem | { finding?: Finding } | { finding?: { id?: string } }): string | undefined {
  return resolveFinding(input)?.id ?? (input as { finding?: { id?: string } } | undefined)?.finding?.id;
}

function resolveFindingFilePath(input?: { filePath?: string } | FindingItem | { finding?: Finding }): string | undefined {
  if (input instanceof FindingItem) {
    return input.finding.filePath;
  }

  const candidate = input as { filePath?: string } | undefined;
  if (candidate?.filePath) {
    return candidate.filePath;
  }

  return resolveFinding(input)?.filePath ?? getCurrentEditorFilePath();
}

function resolvePolicyId(input?: { policyId?: string | null } | FindingItem | { finding?: Finding }): string | undefined {
  if (input instanceof FindingItem) {
    return input.finding.policyId ?? undefined;
  }

  const candidate = input as { policyId?: string | null } | undefined;
  if (candidate?.policyId) {
    return candidate.policyId ?? undefined;
  }

  return resolveFinding(input as FindingItem | { finding?: Finding } | undefined)?.policyId ?? undefined;
}

function countOpenFindingsForFile(filePath: string): number {
  return activeFindings.filter((finding) => finding.filePath === filePath && finding.status === "open").length;
}

function notifyFileDelta(
  filePath: string,
  beforeCount: number,
  afterCount: number,
  trigger: "manual" | "save" | "idle" | "code-action",
): void {
  if (trigger === "manual") {
    return;
  }

  if (beforeCount === afterCount) {
    return;
  }

  const fileLabel = getRelativeFileLabel(filePath);

  if (afterCount < beforeCount) {
    const cleared = beforeCount - afterCount;
    const remainText = afterCount === 0 ? "No open findings remain." : `${afterCount} open finding(s) remain.`;
    vscode.window.showInformationMessage(`Vardionix: Cleared ${cleared} warning(s) in ${fileLabel}. ${remainText}`);
    return;
  }

  const added = afterCount - beforeCount;
  vscode.window.showWarningMessage(`Vardionix: ${added} new warning(s) detected in ${fileLabel}. ${afterCount} open finding(s) now.`);
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

function showScanSummary(
  totalFindings: number,
  totalExcluded: number,
  scope: string,
  findingsBySeverity?: Record<string, number>,
): void {
  if (totalFindings === 0 && totalExcluded === 0) {
    vscode.window.showInformationMessage(`Vardionix: No issues found in ${scope}.`);
    return;
  }

  const counts = findingsBySeverity ?? findingsTreeProvider.getSeverityCounts();
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
