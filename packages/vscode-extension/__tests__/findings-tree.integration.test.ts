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
  it("keeps only open active findings and groups by effective severity", () => {
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
        id: "F-closed",
        severity: "critical",
        status: "dismissed",
        title: "Dismissed issue",
        message: "Dismissed",
        filePath: "/repo/src/closed.js",
        startLine: 5,
        endLine: 5,
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
    ] as any);

    // Only open findings kept
    expect(provider.getFindings().map((f) => f.id)).toEqual(["F-low", "F-high"]);

    // Root children are severity groups
    const groups = provider.getChildren();
    expect(groups.map((g) => g.label)).toEqual(["Critical", "Low"]);

    // Children of severity group are findings
    const criticalFindings = provider.getChildren(groups[0]);
    expect(criticalFindings).toHaveLength(1);
    expect(criticalFindings[0].label).toBe("Escalated issue");
    expect(criticalFindings[0].description).toBe("src/high.js:8");

    const lowFindings = provider.getChildren(groups[1]);
    expect(lowFindings).toHaveLength(1);
    expect(lowFindings[0].label).toBe("Low issue");

    // Severity counts
    const counts = provider.getSeverityCounts();
    expect(counts).toEqual({ critical: 1, low: 1 });
  });
});
