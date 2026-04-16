import { beforeEach, describe, expect, it, vi } from "vitest";
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "fs";
import { join } from "path";

const mcpRegisterState = vi.hoisted(() => ({
  homeDir: `/tmp/vardionix-mcp-register-${Math.random().toString(16).slice(2)}`,
}));

vi.mock("os", async () => {
  const actual = await vi.importActual<typeof import("os")>("os");
  return {
    ...actual,
    homedir: () => mcpRegisterState.homeDir,
  };
});

import {
  installMcpServer,
  verifyMcpServerRegistration,
} from "../src/mcp-register.js";

describe("MCP registration integration", () => {
  beforeEach(() => {
    rmSync(mcpRegisterState.homeDir, { recursive: true, force: true });
    mkdirSync(mcpRegisterState.homeDir, { recursive: true });
  });

  it("installs and verifies Claude Code MCP configuration", () => {
    const context = makeExtensionContext();

    const result = installMcpServer(context, "claude");
    const settingsPath = join(mcpRegisterState.homeDir, ".claude", "settings.json");

    expect(result.verified).toBe(true);
    expect(existsSync(settingsPath)).toBe(true);
    expect(JSON.parse(readFileSync(settingsPath, "utf-8"))).toMatchObject({
      mcpServers: {
        vardionix: {
          command: "node",
          args: [join(context.extensionPath, "dist", "mcp-server.js")],
        },
      },
    });
    expect(verifyMcpServerRegistration(context, "claude")).toBe(true);
  });

  it("installs and verifies Codex MCP configuration without removing other sections", () => {
    const context = makeExtensionContext();
    const configPath = join(mcpRegisterState.homeDir, ".codex", "config.toml");

    mkdirSync(join(mcpRegisterState.homeDir, ".codex"), { recursive: true });
    writeFileSync(
      configPath,
      [
        "[profile.default]",
        'model = "gpt-5"',
        "",
        "[mcp_servers.vardionix]",
        'command = "node"',
        'args = ["/old/path.js"]',
        "",
        "[projects.\"/repo\"]",
        'trust = "trusted"',
      ].join("\n"),
      "utf-8",
    );

    const result = installMcpServer(context, "codex");
    const content = readFileSync(configPath, "utf-8");

    expect(result.verified).toBe(true);
    expect(content).toContain("[profile.default]");
    expect(content).toContain('[projects."/repo"]');
    expect(content).toContain("[mcp_servers.vardionix]");
    expect(content).toContain(`args = ["${join(context.extensionPath, "dist", "mcp-server.js").replace(/\\/g, "\\\\")}"]`);
    expect(content).not.toContain("/old/path.js");
    expect(verifyMcpServerRegistration(context, "codex")).toBe(true);
  });
});

function makeExtensionContext() {
  const extensionPath = join(mcpRegisterState.homeDir, "extension");
  mkdirSync(join(extensionPath, "dist"), { recursive: true });
  writeFileSync(join(extensionPath, "dist", "mcp-server.js"), "console.log('mcp');", "utf-8");

  return {
    extensionPath,
  } as any;
}
