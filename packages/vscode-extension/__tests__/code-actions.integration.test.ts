import { describe, expect, it, vi } from "vitest";

vi.mock("vscode", () => ({
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
}));

import { VardionixCodeActionProvider } from "../src/code-actions.js";

describe("VardionixCodeActionProvider", () => {
  it("offers explain, dismiss, policy, and rescan quick fixes for vardionix diagnostics", () => {
    const provider = new VardionixCodeActionProvider();
    const actions = provider.provideCodeActions(
      {} as never,
      {} as never,
      {
        diagnostics: [
          {
            source: "vardionix",
            data: {
              findingId: "F-1",
              policyId: "POL-1",
              filePath: "/repo/src/app.js",
            },
          },
        ],
      } as never,
    );

    expect(actions.map((action) => action.title)).toEqual([
      "Explain finding",
      "Dismiss finding",
      "Rescan this file",
      "Show policy",
    ]);
    expect((actions[2].command as { command: string }).command).toBe("vardionix.rescanFindingFile");
  });
});
