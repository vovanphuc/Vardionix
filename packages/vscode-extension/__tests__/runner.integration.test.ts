import { beforeEach, describe, expect, it, vi } from "vitest";

const runnerState = vi.hoisted(() => ({
  exists: new Set<string>(),
  execFileSync: vi.fn(),
  execFile: vi.fn(),
  dirname: "/repo/packages/vscode-extension/dist",
}));

vi.mock("node:path", async () => {
  const actual = await vi.importActual<typeof import("node:path")>("node:path");
  return {
    ...actual,
    dirname: vi.fn(() => runnerState.dirname),
  };
});

vi.mock("node:fs", () => ({
  existsSync: (path: string) => runnerState.exists.has(path),
}));

vi.mock("node:child_process", () => ({
  execFileSync: (...args: any[]) => runnerState.execFileSync(...args),
  execFile: (...args: any[]) => runnerState.execFile(...args),
}));

import { runVardionix } from "../src/runner";

describe("runVardionix integration", () => {
  beforeEach(() => {
    runnerState.exists.clear();
    runnerState.execFileSync.mockReset();
    runnerState.execFile.mockReset();
    runnerState.dirname = "/repo/packages/vscode-extension/dist";
  });

  it("prefers the bundled CLI and parses JSON output", async () => {
    runnerState.exists.add("/repo/packages/vscode-extension/dist/cli.js");
    runnerState.exists.add("/repo/packages/vscode-extension/dist/dist/cli.js");
    runnerState.execFile.mockImplementation((_command, _args, _opts, callback) => {
      callback(null, "{\"ok\":true}", "");
    });

    const result = await runVardionix(["findings", "list"], "/repo");

    expect(result).toEqual({
      success: true,
      data: { ok: true },
    });
    expect(runnerState.execFile).toHaveBeenCalledWith(
      "node",
      ["/repo/packages/vscode-extension/dist/dist/cli.js", "findings", "list", "--json"],
      expect.objectContaining({ cwd: "/repo" }),
      expect.any(Function),
    );
  });

  it("falls back to npx when no bundled or monorepo CLI exists", async () => {
    runnerState.execFileSync.mockReturnValue("0.1.0");
    runnerState.execFile.mockImplementation((_command, _args, _opts, callback) => {
      callback(new Error("plain text"), "plain text response", "");
    });

    const result = await runVardionix(["policy", "list"], "/repo");

    expect(runnerState.execFileSync).toHaveBeenCalledWith(
      "npx",
      ["vardionix", "--version"],
      expect.any(Object),
    );
    expect(runnerState.execFile).toHaveBeenCalledWith(
      "npx",
      ["vardionix", "policy", "list", "--json"],
      expect.objectContaining({ cwd: "/repo" }),
      expect.any(Function),
    );
    expect(result).toEqual({
      success: true,
      data: "plain text response",
    });
  });
});
