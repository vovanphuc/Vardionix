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
    tooltip?: string;
    contextValue?: string;
    iconPath?: unknown;
    command?: unknown;

    constructor(label: string) {
      this.label = label;
    }
  }

  class ThemeIcon {
    constructor(public id: string) {}
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
    Range,
    TreeItemCollapsibleState: {
      None: 0,
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
  it("keeps only open active findings and orders by effective severity", () => {
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

    const children = provider.getChildren();

    expect(provider.getFindings().map((finding) => finding.id)).toEqual(["F-low", "F-high"]);
    expect(children.map((item) => item.finding.id)).toEqual(["F-high", "F-low"]);
    expect(children[0].description).toBe("src/high.js:8");
  });
});
