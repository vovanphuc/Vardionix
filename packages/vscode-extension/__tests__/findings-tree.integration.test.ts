import { describe, expect, it, vi } from "vitest";

const vscodeState = vi.hoisted(() => ({
  workspaceFolders: [{ uri: { fsPath: "/repo" } }],
}));

vi.mock("vscode", () => {
  class EventEmitter<T> {
    event = vi.fn();
    fire = vi.fn((_value?: T) => {});
  }

  class TreeItem {
    label: string;
    description?: string;
    tooltip?: unknown;
    contextValue?: string;
    iconPath?: unknown;
    command?: unknown;
    collapsibleState?: number;

    constructor(label: string, collapsibleState?: number) {
      this.label = label;
      this.collapsibleState = collapsibleState;
    }
  }

  class ThemeIcon {
    constructor(public id: string, public color?: unknown) {}
  }

  class ThemeColor {
    constructor(public id: string) {}
  }

  class MarkdownString {
    value: string;
    constructor(value?: string) { this.value = value ?? ""; }
  }

  class Range {
    constructor(
      public startLine: number,
      public startCharacter: number,
      public endLine: number,
      public endCharacter: number,
    ) {}
  }

  return {
    EventEmitter,
    TreeItem,
    ThemeIcon,
    ThemeColor,
    DiagnosticSeverity: {
      Error: 0,
      Warning: 1,
      Information: 2,
      Hint: 3,
    },
    MarkdownString,
    Range,
    TreeItemCollapsibleState: {
      None: 0,
      Collapsed: 1,
      Expanded: 2,
    },
    Uri: {
      file: (path: string) => ({ fsPath: path }),
    },
    workspace: {
      get workspaceFolders() {
        return vscodeState.workspaceFolders;
      },
    },
  };
});

import { FindingsTreeProvider } from "../src/findings-tree.js";

describe("FindingsTreeProvider integration", () => {
  it("groups findings by file and keeps pending verification separate", () => {
    const provider = new FindingsTreeProvider();

    provider.setFindings([
      {
        kind: "active",
        id: "F-low",
        severity: "low",
        status: "open",
        title: "Low issue",
        message: "Low issue",
        filePath: "/repo/src/low.js",
        startLine: 3,
        endLine: 3,
      },
      {
        kind: "active",
        id: "F-high",
        severity: "medium",
        policySeverityOverride: "critical",
        status: "open",
        title: "Escalated issue",
        message: "Escalated",
        filePath: "/repo/src/high.js",
        startLine: 8,
        endLine: 8,
      },
      {
        kind: "active",
        id: "F-pending",
        severity: "medium",
        status: "open",
        title: "Pending issue",
        message: "Pending",
        filePath: "/repo/src/pending.js",
        startLine: 10,
        endLine: 10,
        pendingVerification: true,
      },
    ] as any);

    expect(provider.getFindings().map((f) => f.id)).toEqual(["F-low", "F-high", "F-pending"]);

    const groups = provider.getChildren();
    expect(groups.map((g) => g.label)).toEqual(["Pending Verification", "src/high.js", "src/low.js"]);

    const pendingFindings = provider.getChildren(groups[0]);
    expect(pendingFindings).toHaveLength(1);
    expect(pendingFindings[0].label).toBe("Pending issue (Pending verification)");

    const highFileSeverities = provider.getChildren(groups[1]);
    expect(highFileSeverities).toHaveLength(1);
    expect(highFileSeverities[0].label).toBe("Critical");

    const highFindings = provider.getChildren(highFileSeverities[0]);
    expect(highFindings).toHaveLength(1);
    expect(highFindings[0].label).toBe("Escalated issue");
    expect(highFindings[0].description).toBe("src/high.js:8");

    const lowFileSeverities = provider.getChildren(groups[2]);
    expect(lowFileSeverities).toHaveLength(1);
    expect(lowFileSeverities[0].label).toBe("Low");

    const lowFindings = provider.getChildren(lowFileSeverities[0]);
    expect(lowFindings).toHaveLength(1);
    expect(lowFindings[0].label).toBe("Low issue");

    // Severity counts
    const counts = provider.getSeverityCounts();
    expect(counts).toEqual({ critical: 1, low: 1 });
  });
});
