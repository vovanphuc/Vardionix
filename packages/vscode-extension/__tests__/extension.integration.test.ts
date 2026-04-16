import { beforeEach, describe, expect, it, vi } from "vitest";

const vscodeState = vi.hoisted(() => ({
  commands: new Map<string, (...args: any[]) => unknown>(),
  panels: [] as Array<{ webview: { html: string } }>,
  informationMessages: [] as string[],
  errorMessages: [] as string[],
  warningMessages: [] as string[],
  quickPickSelectionIndex: 0,
  updateDiagnostics: vi.fn(),
  runVardionix: vi.fn(),
  findingsTreeInstances: [] as Array<{
    findings: unknown[];
    setFindings: (findings: unknown[]) => void;
    getSeverityCounts: () => Record<string, number>;
  }>,
  ensureSemgrep: vi.fn(() => Promise.resolve()),
  hasSemgrepAvailable: vi.fn(() => true),
}));

vi.mock("vscode", () => ({
  window: {
    createTreeView: vi.fn(() => ({ dispose: vi.fn() })),
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
  },
  workspace: {
    workspaceFolders: [{ uri: { fsPath: "/repo" } }],
    getConfiguration: vi.fn(() => ({
      get: vi.fn(() => false),
    })),
    onDidSaveTextDocument: vi.fn(() => ({ dispose: vi.fn() })),
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
  },
  StatusBarAlignment: { Left: 1, Right: 2 },
  ThemeColor: class ThemeColor { constructor(public id: string) {} },
  ProgressLocation: { Notification: 1 },
  ViewColumn: { Beside: 2 },
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
}));

vi.mock("../src/semgrep-downloader.ts", () => ({
  ensureSemgrep: (...args: any[]) => vscodeState.ensureSemgrep(...args),
  hasSemgrepAvailable: () => vscodeState.hasSemgrepAvailable(),
  getSemgrepPath: () => "semgrep",
  waitForSemgrep: () => Promise.resolve(),
}));

vi.mock("../src/findings-tree.ts", () => ({
  FindingsTreeProvider: class FakeFindingsTreeProvider {
    findings: unknown[] = [];

    constructor() {
      vscodeState.findingsTreeInstances.push(this);
    }

    setFindings(findings: unknown[]) {
      this.findings = findings;
    }

    getFindings() {
      return this.findings;
    }

    getSeverityCounts() {
      const counts: Record<string, number> = {};
      for (const f of this.findings as any[]) {
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
    vscodeState.panels.length = 0;
    vscodeState.informationMessages.length = 0;
    vscodeState.errorMessages.length = 0;
    vscodeState.warningMessages.length = 0;
    vscodeState.quickPickSelectionIndex = 0;
    vscodeState.updateDiagnostics.mockReset();
    vscodeState.runVardionix.mockReset();
    vscodeState.findingsTreeInstances.length = 0;
    vscodeState.ensureSemgrep.mockClear();
    vscodeState.hasSemgrepAvailable.mockReset();
    vscodeState.hasSemgrepAvailable.mockReturnValue(true);
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
      ["findings", "list", "--open-only", "--workspace", "/repo"],
      "/repo",
    );
    expect(vscodeState.findingsTreeInstances).toHaveLength(1);
    expect(vscodeState.findingsTreeInstances[0].findings).toEqual([
      expect.objectContaining({ id: "F-open", kind: "active" }),
    ]);
    expect(vscodeState.updateDiagnostics).toHaveBeenCalledWith(
      expect.any(Object),
      [
        expect.objectContaining({ id: "F-open" }),
      ],
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
});
