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
    const workspaceRoot = join(mcpRegisterState.homeDir, "repo");

    const result = installMcpServer(context, "claude", workspaceRoot);
    const settingsPath = join(mcpRegisterState.homeDir, ".claude.json");

    expect(result.verified).toBe(true);
    expect(existsSync(settingsPath)).toBe(true);
    expect(JSON.parse(readFileSync(settingsPath, "utf-8"))).toMatchObject({
      projects: {
        [workspaceRoot]: {
          mcpServers: {
            vardionix: {
              command: "node",
              args: [join(context.extensionPath, "dist", "mcp-server.js")],
            },
          },
        },
      },
    });
    expect(verifyMcpServerRegistration(context, "claude", workspaceRoot)).toBe(true);
  });

  it("preserves other Claude Code projects and top-level settings", () => {
    const context = makeExtensionContext();
    const workspaceRoot = join(mcpRegisterState.homeDir, "repo");
    const configPath = join(mcpRegisterState.homeDir, ".claude.json");

    writeFileSync(
      configPath,
      JSON.stringify(
        {
          theme: "dark",
          projects: {
            "/another/project": {
              mcpServers: {
                other: {
                  command: "node",
                  args: ["/tmp/other.js"],
                },
              },
            },
          },
        },
        null,
        2,
      ),
      "utf-8",
    );

    installMcpServer(context, "claude", workspaceRoot);

    expect(JSON.parse(readFileSync(configPath, "utf-8"))).toMatchObject({
      theme: "dark",
      projects: {
        "/another/project": {
          mcpServers: {
            other: {
              command: "node",
              args: ["/tmp/other.js"],
            },
          },
        },
        [workspaceRoot]: {
          mcpServers: {
            vardionix: {
              command: "node",
              args: [join(context.extensionPath, "dist", "mcp-server.js")],
            },
          },
        },
      },
    });
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
