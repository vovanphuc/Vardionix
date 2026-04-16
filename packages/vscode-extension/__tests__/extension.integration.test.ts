import { beforeEach, describe, expect, it, vi } from "vitest";

const vscodeState = vi.hoisted(() => ({
  commands: new Map<string, (...args: any[]) => unknown>(),
  codeActionProviders: [] as unknown[],
  panels: [] as Array<{ webview: { html: string } }>,
  informationMessages: [] as string[],
  errorMessages: [] as string[],
  warningMessages: [] as string[],
  outputLines: [] as string[],
  openedDocuments: [] as Array<{ language?: string; content?: string }>,
  clipboardWrites: [] as string[],
  onDidSaveTextDocument: undefined as ((doc: any) => unknown) | undefined,
  onDidChangeTextDocument: undefined as ((event: any) => unknown) | undefined,
  onDidCloseTextDocument: undefined as ((doc: any) => unknown) | undefined,
  onDidChangeActiveTextEditor: undefined as ((editor: any) => unknown) | undefined,
  quickPickSelectionIndex: 0,
  updateDiagnostics: vi.fn(),
  runVardionix: vi.fn(),
  findingsTreeInstances: [] as Array<{
    findings: unknown[];
    grouping?: string;
    setFindings: (findings: unknown[]) => void;
    setGrouping: (grouping: string) => void;
    getSeverityCounts: () => Record<string, number>;
  }>,
  ensureSemgrep: vi.fn(() => Promise.resolve()),
  hasSemgrepAvailable: vi.fn(() => true),
  lastSemgrepSetupError: undefined as string | undefined,
  installMcpServer: vi.fn(() => ({ updated: true, verified: true })),
  verifyMcpServerRegistration: vi.fn(() => true),
}));

vi.mock("vscode", () => ({
  window: {
    createTreeView: vi.fn(() => ({ dispose: vi.fn(), description: "", message: "" })),
    createOutputChannel: vi.fn(() => ({
      appendLine: vi.fn((line: string) => {
        vscodeState.outputLines.push(line);
      }),
      show: vi.fn(),
      dispose: vi.fn(),
    })),
    createStatusBarItem: vi.fn(() => ({
      text: "",
      tooltip: "",
      command: "",
      name: "",
      backgroundColor: undefined,
      show: vi.fn(),
      hide: vi.fn(),
      dispose: vi.fn(),
    })),
    withProgress: vi.fn(async (_options, task) => task({ report: vi.fn() })),
    showInformationMessage: vi.fn((message: string) => {
      vscodeState.informationMessages.push(message);
      return Promise.resolve(message);
    }),
    showErrorMessage: vi.fn((message: string) => {
      vscodeState.errorMessages.push(message);
      return Promise.resolve(message);
    }),
    showWarningMessage: vi.fn((message: string) => {
      vscodeState.warningMessages.push(message);
      return Promise.resolve(message);
    }),
    showQuickPick: vi.fn(async (items: Array<any>) => items[vscodeState.quickPickSelectionIndex]),
    createWebviewPanel: vi.fn(() => {
      const panel = { webview: { html: "" } };
      vscodeState.panels.push(panel);
      return panel;
    }),
    showTextDocument: vi.fn(async (document: any) => document),
    activeTextEditor: { document: { uri: { scheme: "file", fsPath: "/repo/src/app.js" } } },
    onDidChangeActiveTextEditor: vi.fn((callback: (editor: any) => unknown) => {
      vscodeState.onDidChangeActiveTextEditor = callback;
      return { dispose: vi.fn() };
    }),
  },
  workspace: {
    workspaceFolders: [{ uri: { fsPath: "/repo" } }],
    getConfiguration: vi.fn(() => ({
      get: vi.fn((_key: string, defaultValue?: any) => defaultValue ?? false),
    })),
    openTextDocument: vi.fn(async (options: any) => {
      vscodeState.openedDocuments.push(options);
      return options;
    }),
    onDidSaveTextDocument: vi.fn((callback: (doc: any) => unknown) => {
      vscodeState.onDidSaveTextDocument = callback;
      return { dispose: vi.fn() };
    }),
    onDidChangeTextDocument: vi.fn((callback: (event: any) => unknown) => {
      vscodeState.onDidChangeTextDocument = callback;
      return { dispose: vi.fn() };
    }),
    onDidCloseTextDocument: vi.fn((callback: (doc: any) => unknown) => {
      vscodeState.onDidCloseTextDocument = callback;
      return { dispose: vi.fn() };
    }),
  },
  commands: {
    registerCommand: vi.fn((name: string, callback: (...args: any[]) => unknown) => {
      vscodeState.commands.set(name, callback);
      return { dispose: vi.fn() };
    }),
  },
  languages: {
    createDiagnosticCollection: vi.fn(() => ({
      clear: vi.fn(),
      set: vi.fn(),
      dispose: vi.fn(),
    })),
    registerCodeActionsProvider: vi.fn((_selector: any, provider: unknown) => {
      vscodeState.codeActionProviders.push(provider);
      return { dispose: vi.fn() };
    }),
  },
  StatusBarAlignment: { Left: 1, Right: 2 },
  ThemeColor: class ThemeColor { constructor(public id: string) {} },
  ProgressLocation: { Notification: 1 },
  ViewColumn: { Beside: 2 },
  CodeActionKind: { QuickFix: "quickfix" },
  CodeAction: class CodeAction {
    title: string;
    kind: string;
    command?: unknown;
    diagnostics?: unknown[];
    isPreferred?: boolean;
    constructor(title: string, kind: string) {
      this.title = title;
      this.kind = kind;
    }
  },
  env: {
    clipboard: {
      writeText: vi.fn(async (text: string) => {
        vscodeState.clipboardWrites.push(text);
      }),
    },
  },
}));

vi.mock("../src/runner.ts", () => ({
  runVardionix: (...args: any[]) => vscodeState.runVardionix(...args),
}));

vi.mock("../src/diagnostics.ts", () => ({
  createDiagnosticCollection: () => ({
    clear: vi.fn(),
    set: vi.fn(),
    dispose: vi.fn(),
  }),
  updateDiagnostics: (...args: any[]) => vscodeState.updateDiagnostics(...args),
  getEffectiveSeverity: (finding: any) => finding.policySeverityOverride ?? finding.severity,
  meetsMinimumSeverity: () => true,
}));

vi.mock("../src/semgrep-downloader.ts", () => ({
  ensureSemgrep: (...args: any[]) => vscodeState.ensureSemgrep(...args),
  getLastSemgrepSetupError: () => vscodeState.lastSemgrepSetupError,
  hasSemgrepAvailable: () => vscodeState.hasSemgrepAvailable(),
  getSemgrepPath: () => "semgrep",
  waitForSemgrep: () => Promise.resolve(),
}));

vi.mock("../src/mcp-register.ts", () => ({
  getMcpTargetLabel: (target: string) => (target === "claude" ? "Claude Code" : "Codex"),
  installMcpServer: (...args: any[]) => vscodeState.installMcpServer(...args),
  verifyMcpServerRegistration: (...args: any[]) => vscodeState.verifyMcpServerRegistration(...args),
}));

vi.mock("../src/findings-tree.ts", () => ({
  FindingsTreeProvider: class FakeFindingsTreeProvider {
    findings: unknown[] = [];
    grouping = "file";

    constructor() {
      vscodeState.findingsTreeInstances.push(this);
    }

    setFindings(findings: unknown[]) {
      this.findings = findings;
    }

    getFindings() {
      return this.findings;
    }

    setGrouping(grouping: string) {
      this.grouping = grouping;
    }

    getSeverityCounts() {
      const counts: Record<string, number> = {};
      for (const f of this.findings as any[]) {
        if (f.pendingVerification || f.status !== "open") {
          continue;
        }
        const sev = f.policySeverityOverride ?? f.severity;
        counts[sev] = (counts[sev] ?? 0) + 1;
      }
      return counts;
    }
  },
  FindingItem: class FakeFindingItem {},
}));

import { activate } from "../src/extension.js";

describe("VS Code extension integration", () => {
  beforeEach(() => {
    vscodeState.commands.clear();
    vscodeState.codeActionProviders.length = 0;
    vscodeState.panels.length = 0;
    vscodeState.informationMessages.length = 0;
    vscodeState.errorMessages.length = 0;
    vscodeState.warningMessages.length = 0;
    vscodeState.outputLines.length = 0;
    vscodeState.openedDocuments.length = 0;
    vscodeState.clipboardWrites.length = 0;
    vscodeState.onDidSaveTextDocument = undefined;
    vscodeState.onDidChangeTextDocument = undefined;
    vscodeState.onDidCloseTextDocument = undefined;
    vscodeState.onDidChangeActiveTextEditor = undefined;
    vscodeState.quickPickSelectionIndex = 0;
    vscodeState.updateDiagnostics.mockReset();
    vscodeState.runVardionix.mockReset();
    vscodeState.findingsTreeInstances.length = 0;
    vscodeState.ensureSemgrep.mockClear();
    vscodeState.hasSemgrepAvailable.mockReset();
    vscodeState.hasSemgrepAvailable.mockReturnValue(true);
    vscodeState.lastSemgrepSetupError = undefined;
    vscodeState.installMcpServer.mockReset();
    vscodeState.installMcpServer.mockReturnValue({ updated: true, verified: true });
    vscodeState.verifyMcpServerRegistration.mockReset();
    vscodeState.verifyMcpServerRegistration.mockReturnValue(true);
  });

  it("loads active findings into the tree and diagnostics via the CLI bridge", async () => {
    vscodeState.runVardionix.mockResolvedValue({
      success: true,
      data: [
        {
          kind: "active",
          id: "F-open",
          severity: "high",
          status: "open",
          title: "Open finding",
          message: "Potential XSS",
          filePath: "/repo/src/app.js",
          startLine: 5,
          endLine: 5,
        },
      ],
    });

    activate({ subscriptions: [], globalStorageUri: { fsPath: "/tmp/storage" } } as any);
    await vscodeState.commands.get("vardionix.listFindings")?.();

    expect(vscodeState.runVardionix).toHaveBeenCalledWith(
      ["findings", "list", "--workspace", "/repo"],
      "/repo",
    );
    expect(vscodeState.findingsTreeInstances).toHaveLength(1);
    expect(vscodeState.findingsTreeInstances[0].findings).toEqual([
      expect.objectContaining({ id: "F-open", kind: "active" }),
    ]);
    expect(vscodeState.findingsTreeInstances[0].grouping).toBe("file");
    expect(vscodeState.updateDiagnostics).toHaveBeenCalledWith(
      expect.any(Object),
      [
        expect.objectContaining({ id: "F-open" }),
      ],
    );
  });

  it("hides edited findings immediately and rescans the file on save", async () => {
    vscodeState.runVardionix
      .mockResolvedValueOnce({
        success: true,
        data: [
          {
            kind: "active",
            id: "F-open",
            severity: "high",
            status: "open",
            title: "Open finding",
            message: "Potential XSS",
            filePath: "/repo/src/app.js",
            startLine: 5,
            endLine: 5,
          },
        ],
      })
      .mockResolvedValueOnce({
        success: true,
        data: { totalFindings: 0, totalExcluded: 0 },
      })
      .mockResolvedValueOnce({
        success: true,
        data: [],
      });

    activate({ subscriptions: [], globalStorageUri: { fsPath: "/tmp/storage" } } as any);
    await vscodeState.commands.get("vardionix.listFindings")?.();

    await vscodeState.onDidChangeTextDocument?.({
      document: {
        isDirty: true,
        uri: { scheme: "file", fsPath: "/repo/src/app.js" },
      },
      contentChanges: [
        {
          range: {
            start: { line: 4 },
            end: { line: 4 },
          },
        },
      ],
    });

    expect(vscodeState.findingsTreeInstances[0].findings).toEqual([
      expect.objectContaining({ id: "F-open", pendingVerification: true }),
    ]);
    expect(vscodeState.updateDiagnostics).toHaveBeenLastCalledWith(
      expect.any(Object),
      [expect.objectContaining({ id: "F-open", pendingVerification: true })],
    );

    await vscodeState.onDidSaveTextDocument?.({
      uri: { scheme: "file", fsPath: "/repo/src/app.js" },
    });
    await Promise.resolve();
    await Promise.resolve();
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(vscodeState.runVardionix).toHaveBeenNthCalledWith(
      2,
      ["scan", "file", "/repo/src/app.js"],
      "/repo",
    );
    expect(vscodeState.runVardionix).toHaveBeenNthCalledWith(
      3,
      ["findings", "list", "--workspace", "/repo"],
      "/repo",
    );
    expect(vscodeState.findingsTreeInstances[0].findings).toEqual([]);
    expect(vscodeState.informationMessages).toContain(
      "Vardionix: Cleared 1 warning(s) in src/app.js. No open findings remain.",
    );
  });

  it("restores hidden findings when a dirty file is closed without saving", async () => {
    vscodeState.runVardionix.mockResolvedValue({
      success: true,
      data: [
        {
          kind: "active",
          id: "F-open",
          severity: "high",
          status: "open",
          title: "Open finding",
          message: "Potential XSS",
          filePath: "/repo/src/app.js",
          startLine: 5,
          endLine: 5,
        },
      ],
    });

    activate({ subscriptions: [], globalStorageUri: { fsPath: "/tmp/storage" } } as any);
    await vscodeState.commands.get("vardionix.listFindings")?.();

    await vscodeState.onDidChangeTextDocument?.({
      document: {
        isDirty: true,
        uri: { scheme: "file", fsPath: "/repo/src/app.js" },
      },
      contentChanges: [
        {
          range: {
            start: { line: 4 },
            end: { line: 4 },
          },
        },
      ],
    });

    expect(vscodeState.findingsTreeInstances[0].findings).toEqual([
      expect.objectContaining({ id: "F-open", pendingVerification: true }),
    ]);

    await vscodeState.onDidCloseTextDocument?.({
      uri: { fsPath: "/repo/src/app.js" },
    });

    expect(vscodeState.findingsTreeInstances[0].findings).toEqual([
      expect.objectContaining({ id: "F-open" }),
    ]);
    expect(vscodeState.updateDiagnostics).toHaveBeenLastCalledWith(
      expect.any(Object),
      [expect.objectContaining({ id: "F-open" })],
    );
  });

  it("renders excluded findings through the dedicated command", async () => {
    vscodeState.runVardionix.mockResolvedValue({
      success: true,
      data: [
        {
          kind: "excluded",
          id: "F-excluded",
          severity: "medium",
          title: "Filtered finding",
          filePath: "/repo/src/ignored.js",
          startLine: 9,
          exclusionReason: "Low confidence",
        },
      ],
    });

    activate({ subscriptions: [], globalStorageUri: { fsPath: "/tmp/storage" } } as any);
    await vscodeState.commands.get("vardionix.listExcludedFindings")?.();

    expect(vscodeState.runVardionix).toHaveBeenCalledWith(
      ["findings", "list", "--excluded", "--workspace", "/repo"],
      "/repo",
    );
    expect(vscodeState.panels).toHaveLength(1);
    expect(vscodeState.panels[0].webview.html).toContain("Low confidence");
    expect(vscodeState.panels[0].webview.html).toContain("F-excluded");
  });

  it("blocks scans when automatic Semgrep setup still has no executable", async () => {
    vscodeState.hasSemgrepAvailable.mockReturnValue(false);

    activate({ subscriptions: [], globalStorageUri: { fsPath: "/tmp/storage" } } as any);
    await vscodeState.commands.get("vardionix.scanWorkspace")?.();

    expect(vscodeState.ensureSemgrep).toHaveBeenCalled();
    expect(vscodeState.runVardionix).not.toHaveBeenCalled();
    expect(vscodeState.errorMessages).toContain(
      "Vardionix: Semgrep setup failed. The extension tried to install Semgrep automatically but it is still unavailable.",
    );
  });

  it("surfaces the last Semgrep setup error when blocking scans", async () => {
    vscodeState.hasSemgrepAvailable.mockReturnValue(false);
    vscodeState.lastSemgrepSetupError =
      "Could not download Semgrep automatically: getaddrinfo ENOTFOUND pypi.org. Install Semgrep manually with: pip install semgrep";

    activate({ subscriptions: [], globalStorageUri: { fsPath: "/tmp/storage" } } as any);
    await vscodeState.commands.get("vardionix.scanWorkspace")?.();

    expect(vscodeState.errorMessages).toContain(
      "Vardionix: Semgrep setup failed. Could not download Semgrep automatically: getaddrinfo ENOTFOUND pypi.org. Install Semgrep manually with: pip install semgrep",
    );
  });

  it("installs MCP integration for the selected agent from the UI command", async () => {
    vscodeState.quickPickSelectionIndex = 0;

    activate({
      subscriptions: [],
      globalStorageUri: { fsPath: "/tmp/storage" },
      extensionPath: "/repo/packages/vscode-extension",
    } as any);
    await vscodeState.commands.get("vardionix.installMcpIntegration")?.();

    expect(vscodeState.installMcpServer).toHaveBeenCalledWith(
      expect.objectContaining({ extensionPath: "/repo/packages/vscode-extension" }),
      "claude",
      "/repo",
    );
    expect(vscodeState.informationMessages).toContain(
      "Vardionix: Claude Code: installed and verified",
    );
  });

  it("verifies MCP integration for the selected agent from the UI command", async () => {
    vscodeState.quickPickSelectionIndex = 1;

    activate({
      subscriptions: [],
      globalStorageUri: { fsPath: "/tmp/storage" },
      extensionPath: "/repo/packages/vscode-extension",
    } as any);
    await vscodeState.commands.get("vardionix.verifyMcpIntegration")?.();

    expect(vscodeState.verifyMcpServerRegistration).toHaveBeenCalledWith(
      expect.objectContaining({ extensionPath: "/repo/packages/vscode-extension" }),
      "codex",
      undefined,
    );
    expect(vscodeState.informationMessages).toContain(
      "Vardionix: MCP verified for Codex.",
    );
  });

  it("prepares a Claude Code fix prompt for a selected finding", async () => {
    vscodeState.runVardionix
      .mockResolvedValueOnce({
        success: true,
        data: [
          {
            kind: "active",
            id: "F-open",
            severity: "high",
            status: "open",
            title: "Open finding",
            message: "Potential XSS",
            filePath: "/repo/src/app.js",
            startLine: 5,
            endLine: 5,
          },
        ],
      })
      .mockResolvedValueOnce({
        success: true,
        data: {
          findingId: "F-open",
          prompt: "## Security Finding Fix Request\n\nFix the XSS issue.",
          contextFiles: ["/repo/src/app.js"],
          finding: {
            id: "F-open",
            severity: "high",
            title: "Open finding",
            filePath: "/repo/src/app.js",
          },
        },
      });

    activate({
      subscriptions: [],
      globalStorageUri: { fsPath: "/tmp/storage" },
      extensionPath: "/repo/packages/vscode-extension",
    } as any);
    await vscodeState.commands.get("vardionix.listFindings")?.();
    await vscodeState.commands.get("vardionix.fixFindingWithClaude")?.({
      finding: { id: "F-open" },
    });

    expect(vscodeState.runVardionix).toHaveBeenNthCalledWith(
      2,
      ["patch", "F-open", "--agent", "claude"],
      "/repo",
    );
    expect(vscodeState.clipboardWrites[0]).toContain("# Vardionix Fix Request for Claude Code");
    expect(vscodeState.clipboardWrites[0]).toContain("finding_fix");
    expect(vscodeState.openedDocuments[0]).toMatchObject({
      language: "markdown",
    });
    expect(vscodeState.informationMessages).toContain(
      'Vardionix: Prepared Claude Code prompt for "Open finding" and copied it to the clipboard.',
    );
  });

  it("warns when preparing a Codex fix prompt without verified MCP setup", async () => {
    vscodeState.verifyMcpServerRegistration.mockReturnValue(false);
    vscodeState.runVardionix
      .mockResolvedValueOnce({
        success: true,
        data: [
          {
            kind: "active",
            id: "F-open",
            severity: "medium",
            status: "open",
            title: "Open finding",
            message: "Potential issue",
            filePath: "/repo/src/app.js",
            startLine: 5,
            endLine: 5,
          },
        ],
      })
      .mockResolvedValueOnce({
        success: true,
        data: {
          findingId: "F-open",
          prompt: "## Security Finding Fix Request\n\nFix it.",
          contextFiles: ["/repo/src/app.js"],
          finding: {
            id: "F-open",
            severity: "medium",
            title: "Open finding",
            filePath: "/repo/src/app.js",
          },
        },
      });

    activate({
      subscriptions: [],
      globalStorageUri: { fsPath: "/tmp/storage" },
      extensionPath: "/repo/packages/vscode-extension",
    } as any);
    await vscodeState.commands.get("vardionix.listFindings")?.();
    await vscodeState.commands.get("vardionix.fixFindingWithCodex")?.({
      finding: { id: "F-open" },
    });

    expect(vscodeState.runVardionix).toHaveBeenNthCalledWith(
      2,
      ["patch", "F-open", "--agent", "codex"],
      "/repo",
    );
    expect(vscodeState.warningMessages).toContain(
      'Vardionix: Prepared Codex prompt for "Open finding" and copied it to the clipboard. Install MCP for Codex if you want the agent to use Vardionix tools directly.',
    );
  });
});
